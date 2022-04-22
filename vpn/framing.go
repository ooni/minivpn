package vpn

import (
	"encoding/binary"
)

func toSizeFrame(b []byte) []byte {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	return append(l, b...)
}
