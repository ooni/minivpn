package vpn

//
// Transports for OpenVPN over TCP and over UDP.
//

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	// ErrBadConnNetwork indicates that the conn's network is neither TCP nor UDP.
	ErrBadConnNetwork = errors.New("bad conn.Network value")

	// ErrPacketTooShort indicates that a packet is too short.
	ErrPacketTooShort = errors.New("packet too short")
)

// TLSModeTransport is a transport for OpenVPN in TLS mode.
//
// See https://openvpn.net/community-resources/openvpn-protocol/ for documentation
// on the protocol used by OpenVPN on the wire.
type TLSModeTransport interface {
	// ReadPacket reads an OpenVPN packet from the wire.
	ReadPacket() (opcodeKeyID uint8, data []byte, err error)

	// WritePacket writes an OpenVPN packet to the wire.
	WritePacket(opcodeKeyID uint8, data []byte) error

	// SetDeadline sets the underlying conn's deadline.
	SetDeadline(deadline time.Time) error

	// SetReadDeadline sets the underlying conn's read deadline.
	SetReadDeadline(deadline time.Time) error

	// SetWriteDeadline sets the underlying conn's write deadline.
	SetWriteDeadline(deadline time.Time) error

	// Close closes the underlying conn.
	Close() error

	// LocalAddr returns the underlying conn's local addr.
	LocalAddr() net.Addr

	// RemoteAddr returns the underlying conn's remote addr.
	RemoteAddr() net.Addr
}

// NewTLSModeTransport creates a new TLSModeTransport using the given net.Conn.
func NewTLSModeTransport(conn net.Conn) (TLSModeTransport, error) {
	switch network := conn.LocalAddr().Network(); network {
	case "tcp", "tcp4", "tcp6":
		return &tlsModeTransportTCP{Conn: conn}, nil
	case "udp", "udp4", "udp6":
		return &tlsModeTransportUDP{Conn: conn}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrBadConnNetwork, network)
	}
}

// tlsModeTransportUDP implements TLSModeTransport for UDP.
type tlsModeTransportUDP struct {
	net.Conn
}

// transportParsePacket is a convenience function for parsing packets.
func transportParsePacket(buff []byte) (uint8, []byte, error) {
	if len(buff) < 1 {
		return 0, nil, ErrPacketTooShort
	}
	opcodeKeyID := buff[0]
	buff = buff[1:]
	return opcodeKeyID, buff, nil
}

func (txp *tlsModeTransportUDP) ReadPacket() (uint8, []byte, error) {
	const enough = 1 << 17
	buff := make([]byte, enough)
	count, err := txp.Conn.Read(buff)
	if err != nil {
		return 0, nil, err
	}
	buff = buff[:count]
	return transportParsePacket(buff)
}

func (txp *tlsModeTransportUDP) WritePacket(opcodeKeyID uint8, data []byte) error {
	var out bytes.Buffer
	out.WriteByte(opcodeKeyID)
	out.Write(data)
	_, err := txp.Conn.Write(out.Bytes())
	return err
}

// tlsModeTransportTCP implements TLSModeTransport for TCP.
type tlsModeTransportTCP struct {
	net.Conn
}

func (txp *tlsModeTransportTCP) ReadPacket() (uint8, []byte, error) {
	lenbuff := make([]byte, 2)
	if _, err := io.ReadFull(txp.Conn, lenbuff); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint16(lenbuff)
	buff := make([]byte, length)
	if _, err := io.ReadFull(txp.Conn, buff); err != nil {
		return 0, nil, err
	}
	return transportParsePacket(buff)
}

func (txp *tlsModeTransportTCP) WritePacket(opcodeKeyID uint8, data []byte) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)))
	var out bytes.Buffer
	out.Write(length)
	out.WriteByte(opcodeKeyID)
	out.Write(data)
	_, err := txp.Conn.Write(out.Bytes())
	return err
}
