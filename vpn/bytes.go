package vpn

//
// Functions operating on bytes
//

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errBadOptLen = errors.New("bad option lenght")
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
func encodeOptionString(s string) []byte {
	if len(s)-1 > 1<<16 {
		panic("string too large")
	}
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(len(s)+1))
	data = append(data, []byte(s)...)
	data = append(data, 0x00)
	return data
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
