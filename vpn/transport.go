package vpn

//
// Transports for OpenVPN over TCP and over UDP.
// This file includes:
// 1. Methods for reading packets from the wire
// 2. A TLS transport that reads and writes TLS records as part of control packets.
//

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

// direct reads on the underlying conn

func readPacket(conn net.Conn) ([]byte, error) {
	switch network := conn.LocalAddr().Network(); network {
	case "tcp", "tcp4", "tcp6":
		return readPacketFromTCP(conn)
	case "udp", "udp4", "upd6":
		// for UDP we don't need to parse size frames
		return readPacketFromUDP(conn)
	default:
		return nil, fmt.Errorf("%w: %s", ErrBadConnNetwork, network)
	}
}

func readPacketFromUDP(conn net.Conn) ([]byte, error) {
	const enough = 1 << 17
	buf := make([]byte, enough)
	count, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:count]
	return buf, nil
}

func readPacketFromTCP(conn net.Conn) ([]byte, error) {
	lenbuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenbuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenbuf)
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// TLSModeTransporter is a transport for OpenVPN in TLS mode.
//
// See https://openvpn.net/community-resources/openvpn-protocol/ for documentation
// on the protocol used by OpenVPN on the wire.
type TLSModeTransporter interface {
	// ReadPacket reads an OpenVPN packet from the wire.
	ReadPacket() (p *packet, err error)

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

// NewTLSModeTransport creates a new TLSModeTransporter using the given net.Conn.
func NewTLSModeTransport(conn net.Conn, s *session) (TLSModeTransporter, error) {
	return &tlsTransport{Conn: conn, session: s}, nil
}

// tlsTransport implements TLSModeTransporter.
type tlsTransport struct {
	net.Conn
	session *session
}

func (t *tlsTransport) ReadPacket() (*packet, error) {
	buf, err := readPacket(t.Conn)
	if err != nil {
		return nil, err
	}

	p, err := parsePacketFromBytes(buf)
	if err != nil {
		return &packet{}, err
	}
	if p.isACK() {
		logger.Warn("tls: got ACK (ignored)")
		return &packet{}, nil
	}
	return p, nil
}

func (t *tlsTransport) WritePacket(opcodeKeyID uint8, data []byte) error {
	p := newPacketFromPayload(opcodeKeyID, 0, data)
	p.id, _ = t.session.LocalPacketID()
	p.localSessionID = t.session.LocalSessionID
	payload := p.Bytes()

	out := maybeAddSizeFrame(t.Conn, payload)

	logger.Debug(fmt.Sprintln("tls write:", len(out)))
	logger.Debug(fmt.Sprintln(hex.Dump(out)))

	_, err := t.Conn.Write(out)
	return err
}

var _ TLSModeTransporter = &tlsTransport{} // Ensure that we implement TLSModelTransporter

// TLSConn implements net.Conn, and is passed to the tls.Client to perform a
// TLS Handshake over OpenVPN control packets.
type TLSConn struct {
	conn      net.Conn
	session   *session
	transport TLSModeTransporter
	// we need a buffer because the tls records request less than the
	// payload we receive.
	bufReader *bytes.Buffer
}

// NewTLSConn returns a TLSConn. It requires the on-the-wire net.Conn that will
// be used underneath, and a configured session. It returns also an error if
// the operation cannot be completed.
func NewTLSConn(conn net.Conn, s *session) (*TLSConn, error) {
	transport, err := NewTLSModeTransport(conn, s)
	if err != nil {
		return &TLSConn{}, err
	}
	buf := bytes.NewBuffer(nil)
	tlsConn := &TLSConn{
		conn:      conn,
		session:   s,
		transport: transport,
		bufReader: buf,
	}
	return tlsConn, err
}

// Read over the control channel. This method implements the reliability layer:
// it retries reads until the _next_ packet is received (according to the
// packetID). Returns also an error if the operation cannot be completed.
func (t *TLSConn) Read(b []byte) (int, error) {
	for {
		switch len(t.session.ackQueue) {
		case 0:
			ok, n, err := t.doReadFromConn(b)
			if ok {
				return n, err
			}
		default:
			ok, n, err := t.doReadFromQueue(b)
			if ok {
				return n, err
			}
		}
	}
}

func (t *TLSConn) doReadFromConn(b []byte) (bool, int, error) {
	p, err := t.doRead()
	if err != nil {
		return true, 0, err
	}
	if t.canRead(p) {
		n, err := t.ackAndRead(b, p)
		return true, n, err
	}
	return false, 0, nil
}

func (t *TLSConn) doReadFromQueue(b []byte) (bool, int, error) {
	for p := range t.session.ackQueue {
		if t.canRead(p) {
			n, err := t.ackAndRead(b, p)
			return true, n, err
		} else {
			t.session.ackQueue <- p
			p, err := t.doRead()
			if err != nil {
				return true, 0, err
			}
			if t.canRead(p) {
				n, err := t.ackAndRead(b, p)
				return true, n, err

			} else {
				if p != nil {
					t.session.ackQueue <- p
				}
			}
		}
	}
	return false, 0, nil
}

func (t *TLSConn) doRead() (*packet, error) {
	return t.transport.ReadPacket()
}

func (t *TLSConn) canRead(p *packet) bool {
	return p != nil && t.session.isNextPacket(p)
}

func (t *TLSConn) ackAndRead(b []byte, p *packet) (int, error) {
	if err := sendACK(t.conn, t.session, p.id); err != nil {
		return 0, err
	}
	t.bufReader.Write(p.payload)
	return t.bufReader.Read(b)
}

func (t *TLSConn) Write(b []byte) (int, error) {
	err := t.transport.WritePacket(uint8(pControlV1), b)
	if err != nil {
		logger.Errorf("tls write: %s", err.Error())
		return 0, err
	}
	return len(b), err
}

func (t *TLSConn) Close() error {
	return t.conn.Close()
}

func (t *TLSConn) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *TLSConn) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

func (t *TLSConn) SetDeadline(tt time.Time) error {
	return t.conn.SetDeadline(tt)
}

func (t *TLSConn) SetReadDeadline(tt time.Time) error {
	return t.conn.SetReadDeadline(tt)
}

func (t *TLSConn) SetWriteDeadline(tt time.Time) error {
	return t.conn.SetWriteDeadline(tt)
}

var _ net.Conn = &TLSConn{} // Ensure that we implement net.Conn
