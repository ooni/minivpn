package networkio

import (
	"net"
	"time"
)

// FramingConn is an OpenVPN network connection that knows about
// the framing used by OpenVPN to read and write raw packets.
type FramingConn interface {
	// ReadRawPacket reads and return a raw OpenVPN packet.
	ReadRawPacket() ([]byte, error)

	// WriteRawPacket writes a raw OpenVPN packet.
	WriteRawPacket(pkt []byte) error

	// SetReadDeadline is like net.Conn.SetReadDeadline.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline is like net.Conn.SetWriteDeadline.
	SetWriteDeadline(t time.Time) error

	// LocalAddr is like net.Conn.LocalAddr.
	LocalAddr() net.Addr

	// RemoteAddr is like net.Conn.RemoteAddr.
	RemoteAddr() net.Addr

	// Close is like net.Conn.Close.
	Close() error
}
