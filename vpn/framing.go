package vpn

import (
	"encoding/binary"
)

// toSizeFrame creates an OpenVPN packet format for TCP.
// the prepended packet lenght words define the packetization of the stream.
// https://openvpn.net/community-resources/openvpn-protocol/
func toSizeFrame(b []byte) []byte {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	return append(l, b...)
}

func sizeFromHeader(b []byte) int {
	if len(b) <= 2 {
		return len(b)
	}
	return int(binary.BigEndian.Uint16(b[:2]))
}
