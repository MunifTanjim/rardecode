package rardecode

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"io/fs"
)

// cipherBlockReader implements Block Mode decryption of an io.Reader object.
type cipherBlockReader struct {
	br     byteReader
	mode   cipher.BlockMode
	inbuf  []byte // raw input blocks not yet decrypted
	outbuf []byte // output buffer used when output slice < block size
	block  []byte // input/output buffer for a single block
}

func (cr *cipherBlockReader) fillOutbuf() error {
	l := len(cr.inbuf)
	_, err := io.ReadFull(cr.br, cr.block[l:])
	if err != nil {
		return err
	}
	cr.mode.CryptBlocks(cr.block, cr.block)
	cr.outbuf = cr.block
	return nil
}

func (cr *cipherBlockReader) ReadByte() (byte, error) {
	if len(cr.outbuf) == 0 {
		err := cr.fillOutbuf()
		if err != nil {
			return 0, err
		}
	}
	b := cr.outbuf[0]
	cr.outbuf = cr.outbuf[1:]
	return b, nil
}

// Read reads and decrypts data into p.
// If the input is not a multiple of the cipher block size,
// the trailing bytes will be ignored.
func (cr *cipherBlockReader) Read(p []byte) (int, error) {
	var n int
	if len(cr.outbuf) > 0 {
		n = copy(p, cr.outbuf)
		cr.outbuf = cr.outbuf[n:]
		return n, nil
	}
	blockSize := cr.mode.BlockSize()
	if len(p) < blockSize {
		// use cr.block as buffer
		err := cr.fillOutbuf()
		if err != nil {
			return 0, err
		}
		n = copy(p, cr.outbuf)
		cr.outbuf = cr.outbuf[n:]
		return n, nil
	}
	// use p as buffer (but round down to multiple of block size)
	p = p[:len(p)-(len(p)%blockSize)]
	l := len(cr.inbuf)
	if l > 0 {
		copy(p, cr.inbuf)
		cr.inbuf = nil
	}
	n, err := io.ReadAtLeast(cr.br, p[l:], blockSize-l)
	if err != nil {
		return 0, err
	}
	n += l
	p = p[:n]
	n -= n % blockSize
	if n != len(p) {
		l = copy(cr.block, p[n:])
		cr.inbuf = cr.block[:l]
		p = p[:n]
	}
	cr.mode.CryptBlocks(p, p)
	return n, nil
}

func (cr *cipherBlockReader) writeToN(w io.Writer, n int64) (int64, error) {
	if n == 0 {
		return 0, nil
	}
	var tot int64
	var err error
	for tot != n && err == nil {
		if len(cr.outbuf) == 0 {
			err = cr.fillOutbuf()
			if err != nil {
				break
			}
		}
		buf := cr.outbuf
		if n > 0 {
			todo := n - tot
			if todo < int64(len(buf)) {
				buf = buf[:todo]
			}
		}
		var l int
		l, err = w.Write(buf)
		tot += int64(l)
		cr.outbuf = cr.outbuf[l:]
	}
	if n < 0 && err == io.EOF {
		err = nil
	}
	return tot, err
}

func (cr *cipherBlockReader) WriteTo(w io.Writer) (int64, error) {
	return cr.writeToN(w, -1)
}

func newCipherBlockReader(r byteReader, mode cipher.BlockMode) *cipherBlockReader {
	return &cipherBlockReader{
		br:    r,
		mode:  mode,
		block: make([]byte, mode.BlockSize()),
	}
}

// newAesDecryptReader returns a cipherBlockReader that decrypts input from a given io.Reader using AES.
func newAesDecryptReader(r byteReader, key, iv []byte) (*cipherBlockReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	return newCipherBlockReader(r, mode), nil
}

type cipherBlockFileReader struct {
	archiveFile
	cbr *cipherBlockReader
}

func (cr *cipherBlockFileReader) ReadByte() (byte, error) {
	return cr.cbr.ReadByte()
}

func (cr *cipherBlockFileReader) Read(p []byte) (int, error) {
	return cr.cbr.Read(p)
}

func (cr *cipherBlockFileReader) WriteTo(w io.Writer) (int64, error) {
	return cr.cbr.WriteTo(w)
}

func (cr *cipherBlockFileReader) writeToN(w io.Writer, n int64) (int64, error) {
	return cr.cbr.writeToN(w, n)
}

func newAesDecryptFileReader(r archiveFile, key, iv []byte) (archiveFile, error) {
	if sr, ok := r.(archiveFileSeeker); ok {
		return newAesDecryptFileReadSeeker(sr, key, iv)
	}
	cbr, err := newAesDecryptReader(r, key, iv)
	if err != nil {
		return nil, err
	}
	return &cipherBlockFileReader{archiveFile: r, cbr: cbr}, nil
}

// cipherBlockFileReadSeeker is a seekable variant of cipherBlockFileReader.
// It implements io.Seeker by re-reading and decrypting from the start.
type cipherBlockFileReadSeeker struct {
	archiveFileSeeker
	cbr    *cipherBlockReader
	key    []byte
	iv     []byte
	offset int64 // current decrypted byte position
	size   int64 // total encrypted data size (decrypted size is the same)
}

func (cr *cipherBlockFileReadSeeker) ReadByte() (byte, error) {
	b, err := cr.cbr.ReadByte()
	if err == nil {
		cr.offset++
	}
	return b, err
}

func (cr *cipherBlockFileReadSeeker) Read(p []byte) (int, error) {
	n, err := cr.cbr.Read(p)
	cr.offset += int64(n)
	return n, err
}

func (cr *cipherBlockFileReadSeeker) WriteTo(w io.Writer) (int64, error) {
	n, err := cr.cbr.WriteTo(w)
	cr.offset += n
	return n, err
}

func (cr *cipherBlockFileReadSeeker) writeToN(w io.Writer, n int64) (int64, error) {
	m, err := cr.cbr.writeToN(w, n)
	cr.offset += m
	return m, err
}

func (cr *cipherBlockFileReadSeeker) Seek(offset int64, whence int) (int64, error) {
	// Calculate absolute offset
	switch whence {
	case io.SeekStart:
		// offset is already absolute
	case io.SeekCurrent:
		offset += cr.offset
	case io.SeekEnd:
		offset += cr.size
	default:
		return 0, fs.ErrInvalid
	}
	if offset < 0 {
		return 0, fs.ErrInvalid
	}

	// O(1) seek using CBC IV reconstruction trick:
	// To decrypt block N, we only need Ciphertext[N-1] as the IV.
	// This avoids decrypting all previous blocks.
	const blockSize = 16 // AES block size
	blockIndex := offset / int64(blockSize)
	blockOffset := int(offset % int64(blockSize))

	var iv []byte
	var err error

	if blockIndex > 0 {
		// Read previous ciphertext block as IV
		cipherPos := (blockIndex - 1) * int64(blockSize)
		_, err = cr.archiveFileSeeker.Seek(cipherPos, io.SeekStart)
		if err != nil {
			return 0, err
		}
		iv = make([]byte, blockSize)
		_, err = io.ReadFull(cr.archiveFileSeeker, iv)
		if err != nil {
			return 0, err
		}
		// Stream is now positioned at start of target block
	} else {
		// For block 0, use original IV
		iv = cr.iv
		_, err = cr.archiveFileSeeker.Seek(0, io.SeekStart)
		if err != nil {
			return 0, err
		}
	}

	// Recreate cipher with reconstructed IV
	cr.cbr, err = newAesDecryptReader(cr.archiveFileSeeker, cr.key, iv)
	if err != nil {
		return 0, err
	}

	// Handle mid-block seek by discarding initial bytes of target block
	if blockOffset > 0 {
		discard := make([]byte, blockOffset)
		_, err = io.ReadFull(cr.cbr, discard)
		if err != nil {
			return 0, err
		}
	}

	cr.offset = offset
	return offset, nil
}

func newAesDecryptFileReadSeeker(r archiveFileSeeker, key, iv []byte) (*cipherBlockFileReadSeeker, error) {
	cbr, err := newAesDecryptReader(r, key, iv)
	if err != nil {
		return nil, err
	}
	// Get the size from the current file header
	h := r.currFile()
	size := h.PackedSize
	return &cipherBlockFileReadSeeker{
		archiveFileSeeker: r,
		cbr:               cbr,
		key:               key,
		iv:                iv,
		size:              size,
	}, nil
}
