package vpn

//
// Functions operating on bytes
//

import (
	"crypto/rand"
	"encoding/binary"
)

// genRandomBytes returns an array of bytes with the given size using
// a CSRNG, on success, or an error, in case of failure.
func genRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func encodeBytes(b []byte) []byte {
	// TODO(bassosimone,ainghazal): this function should either return
	// an error, or panic, if given more than 1<<16 bytes.
	//
	// TODO(bassosimone,ainghazal): I would expected this function to have
	// a slightly more descriptive name. What is the name of the encoding
	// we're actually using here?
	//
	// TODO(bassosimone,ainghazal): I am surprised the function that deals
	// with decoding is not implemented here. I would have expected the
	// function to encode and the function to decode to be side by side.
	//
	// TODO(bassosimone,ainghazal): document this function once we have
	// figure out what the proper name for it should actually be.
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(len(b)+1))
	data = append(data, b...)
	data = append(data, 0x00)
	return data
}
