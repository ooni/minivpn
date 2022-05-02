package vpn

//
// Deals with OpenVPN framing in TCP mode.
//
// TODO(ainghazal, bassosimone): move to bytes.go?

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

// sizeFromHeader reads the size header and returns the encoded buffer length
func sizeFromHeader(b []byte) int {
	if len(b) <= 2 {
		// TODO(ainghazal): what's the right thing to return here?
		// this was probably just a quick addition while debugging, but
		// very likely not correct.
		return len(b)
	}
	return int(binary.BigEndian.Uint16(b[:2]))
}
