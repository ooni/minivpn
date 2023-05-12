package networkio

import (
	"math"
	"net"
)

// DatagramConn wraps a datagram socket and implements OpenVPN framing.
type DatagramConn struct {
	net.Conn
}

var _ FramingConn = &DatagramConn{}

// ReadRawPacket implements FramingConn
func (c *DatagramConn) ReadRawPacket() ([]byte, error) {
	buffer := make([]byte, math.MaxUint16) // maximum UDP datagram size
	count, err := c.Read(buffer)
	if err != nil {
		return nil, err
	}
	pkt := buffer[:count]
	return pkt, nil
}

// WriteRawPacket implements FramingConn
func (c *DatagramConn) WriteRawPacket(pkt []byte) error {
	if len(pkt) > math.MaxUint16 {
		return ErrPacketTooLarge
	}
	_, err := c.Conn.Write(pkt)
	return err
}
