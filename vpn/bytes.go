package vpn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

func genRandomBytes(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = rand.Read(b)
	if err != nil {
		return b, err
	}
	return b, err
}

func areBytesEqual(s1, s2 []byte) bool {
	return 0 == bytes.Compare(s1, s2)
}

func encodeBytes(b []byte) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(len(b)+1))
	data = append(data, b...)
	data = append(data, 0x00)
	return data
}
