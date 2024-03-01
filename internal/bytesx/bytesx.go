// Package bytesx provides functions operating on bytes.
//
// Specifically we implement these operations:
//
// 1. generating random bytes;
//
// 2. OpenVPN options encoding and decoding;
//
// 3. PKCS#7 padding and unpadding.
package bytesx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ooni/minivpn/internal/runtimex"
)

var (
	// ErrEncodeOption indicates an option encoding error occurred.
	ErrEncodeOption = errors.New("can't encode option")

	// ErrDecodeOption indicates an option decoding error occurred.
	ErrDecodeOption = errors.New("can't decode option")

	// ErrPaddingPKCS7 indicates that a PKCS#7 padding error has occurred.
	ErrPaddingPKCS7 = errors.New("PKCS#7 padding error")

	// ErrUnpaddingPKCS7 indicates that a PKCS#7 unpadding error has occurred.
	ErrUnpaddingPKCS7 = errors.New("PKCS#7 unpadding error")
)

// genRandomBytes returns an array of bytes with the given size using
// a CSRNG, on success, or an error, in case of failure.
func GenRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

// EncodeOptionStringToBytes is used to encode the options string, username and password.
//
// According to the OpenVPN protocol, options are represented as a two-byte word,
// plus the byte representation of the string, null-terminated.
//
// See https://openvpn.net/community-resources/openvpn-protocol/.
//
// This function returns errEncodeOption in case of failure.
func EncodeOptionStringToBytes(s string) ([]byte, error) {
	if len(s) >= math.MaxUint16 { // Using >= b/c we need to account for the final \0
		return nil, fmt.Errorf("%w:%s", ErrEncodeOption, "string too large")
	}
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(len(s))+1)
	data = append(data, []byte(s)...)
	data = append(data, 0x00)
	return data, nil
}

// DecodeOptionStringFromBytes returns the string-value for the null-terminated string
// returned by the server when sending remote options to us.
//
// This function returns errDecodeOption on failure.
func DecodeOptionStringFromBytes(b []byte) (string, error) {
	if len(b) < 2 {
		return "", fmt.Errorf("%w: expected at least two bytes", ErrDecodeOption)
	}
	length := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:] // skip over the length
	// the server sends padding, so we cannot do a strict check
	if len(b) < length {
		return "", fmt.Errorf("%w: got %d, expected %d", ErrDecodeOption, len(b), length)
	}
	if len(b) <= 0 || length == 0 {
		return "", fmt.Errorf("%w: zero length encoded option is not possible: %s", ErrDecodeOption,
			"we need at least one byte for the trailing \\0")
	}
	if b[length-1] != 0x00 {
		return "", fmt.Errorf("%w: missing trailing \\0", ErrDecodeOption)
	}
	return string(b[:len(b)-1]), nil
}

// BytesUnpadPKCS7 performs the PKCS#7 unpadding of a byte array.
func BytesUnpadPKCS7(b []byte, blockSize int) ([]byte, error) {
	// 1. check whether we can unpad at all
	if blockSize > math.MaxUint8 {
		return nil, fmt.Errorf("%w: blockSize too large", ErrUnpaddingPKCS7)
	}
	// 2. trivial case
	if len(b) <= 0 {
		return nil, fmt.Errorf("%w: passed empty buffer", ErrUnpaddingPKCS7)
	}
	// 4. read the padding size
	psiz := int(b[len(b)-1])
	// 5. enforce padding size constraints
	if psiz <= 0x00 {
		return nil, fmt.Errorf("%w: padding size cannot be zero", ErrUnpaddingPKCS7)
	}
	if psiz > blockSize {
		return nil, fmt.Errorf("%w: padding size cannot be larger than blockSize", ErrUnpaddingPKCS7)
	}
	// 6. compute the padding offset
	off := len(b) - psiz
	// 7. return unpadded bytes
	runtimex.Assert(off >= 0 && off <= len(b), "off is out of bounds")
	return b[:off], nil
}

// bytesPadPKCS7 returns the PKCS#7 padding of a byte array.
func BytesPadPKCS7(b []byte, blockSize int) ([]byte, error) {
	runtimex.PanicIfTrue(blockSize <= 0, "blocksize cannot be negative or zero")

	// If lth mod blockSize == 0, then the input gets appended a whole block size
	// See https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
	if blockSize > math.MaxUint8 {
		// This padding method is well defined iff blockSize is less than 256.
		return nil, ErrPaddingPKCS7
	}
	psiz := blockSize - len(b)%blockSize
	padding := bytes.Repeat([]byte{byte(psiz)}, psiz)
	return append(b, padding...), nil
}

// ReadUint32 is a convenience function that reads a uint32 from a 4-byte
// buffer, returning an error if the operation failed.
func ReadUint32(buf *bytes.Buffer) (uint32, error) {
	var numBuf [4]byte
	_, err := io.ReadFull(buf, numBuf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(numBuf[:]), nil
}

// WriteUint32 is a convenience function that appends to the given buffer
// 4 bytes containing the big-endian representation of the given uint32 value.
// Caller is responsible to ensure the passed value does not overflow the
// maximal capacity of 4 bytes.
func WriteUint32(buf *bytes.Buffer, val uint32) {
	var numBuf [4]byte
	binary.BigEndian.PutUint32(numBuf[:], val)
	buf.Write(numBuf[:])
}

// WriteUint24 is a convenience function that appends to the given buffer
// 3 bytes containing the big-endian representation of the given uint32 value.
// Caller is responsible to ensure the passed value does not overflow the
// maximal capacity of 3 bytes.
func WriteUint24(buf *bytes.Buffer, val uint32) {
	b := &bytes.Buffer{}
	WriteUint32(b, val)
	buf.Write(b.Bytes()[1:])
}
