package networkio

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
)

// StreamConn wraps a stream socket and implements OpenVPN framing.
type StreamConn struct {
	net.Conn
}

var _ FramingConn = &StreamConn{}

// ReadRawPacket implements FramingConn
func (c *StreamConn) ReadRawPacket() ([]byte, error) {
	lenbuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenbuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenbuf)
	buf := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ErrPacketTooLarge means that a packet is larger than [math.MaxUint16].
var ErrPacketTooLarge = errors.New("openvpn: packet too large")

// WriteRawPacket implements FramingConn
func (c *StreamConn) WriteRawPacket(pkt []byte) error {
	if len(pkt) > math.MaxUint16 {
		return ErrPacketTooLarge
	}
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(pkt)))
	pkt = append(length, pkt...)
	_, err := c.Conn.Write(pkt)
	return err
}
