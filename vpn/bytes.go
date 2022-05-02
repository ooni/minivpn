package vpn

//
// Functions operating on bytes
//

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errBadOptLen = errors.New("bad option length")
)

// genRandomBytes returns an array of bytes with the given size using
// a CSRNG, on success, or an error, in case of failure.
func genRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

// encodeOptionString is used to encode the options string, username and password.
// According to the OpenVPN protocol, they are represented as a two-byte word,
// plus the byte representation of the string, null-terminated.
// https://openvpn.net/community-resources/openvpn-protocol/
func encodeOptionString(s string) ([]byte, error) {
	if len(s) > 1<<16-1 {
		return nil, fmt.Errorf("%w:%s", errBadOptLen, "string too large")
	}
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(len(s))+1)
	data = append(data, []byte(s)...)
	data = append(data, 0x00)
	return data, nil
}

// decodeOptionString returns the string-value for the null-terminated string
// returned by the server when sending the remote options to us.
func decodeOptionString(b []byte) (string, error) {
	l := int(binary.BigEndian.Uint16(b[:2])) - 1
	if len(b) < l+2 {
		return "", fmt.Errorf("%w: got %d, expected %d", errBadOptLen, len(b), l+2)
	}
	return string(b[2:l]), nil
}

// unpadTextPKCS7 does PKCS#7 unpadding of a byte array.
// we don't use the block size to unpad, only to do a sanity check.
func unpadTextPKCS7(b []byte, bs int) ([]byte, error) {
	if bs >= 1<<8 {
		// This padding method is well defined iff k is less
		// than 256.
		return nil, errPadding
	}
	// trivial case
	if len(b) == 0 {
		return nil, errPadding
	}
	p := int(b[len(b)-1])
	//  the deciphering algorithm can always treat the last byte as a pad
	//  byte, but the zero value is forbidden.
	if p == 0 {
		return nil, errPadding
	}
	if p > bs {
		// malformed input
		return nil, fmt.Errorf("%w: got bad padding len: %v", errPadding, p)
	}
	return b[:len(b)-p], nil
}

// padTextPKCS7 does PKCS#7 padding of a byte array.
// If lth mod bs = 0, then the input gets appended a whole block size
// See https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
func padTextPKCS7(b []byte, bs int) ([]byte, error) {
	if bs >= 1<<8 {
		// This padding method is well defined iff k is less
		// than 256.
		return nil, errPadding
	}
	p := bs - len(b)%bs
	t := bytes.Repeat([]byte{byte(p)}, p)
	return append(b, t...), nil
}
