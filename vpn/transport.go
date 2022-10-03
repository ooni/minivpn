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

// tlsModeTransporter is a transport for OpenVPN in TLS mode.
//
// See https://openvpn.net/community-resources/openvpn-protocol/ for documentation
// on the protocol used by OpenVPN on the wire.
type tlsModeTransporter interface {
	// ReadPacket reads an OpenVPN packet from the wire.
	// TODO should select and return first packet??
	ReadPacket() (*packet, error)

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

// newTLSModeTransport creates a new TLSModeTransporter using the given net.Conn.
func newTLSModeTransport(conn net.Conn, r *reliableTransport) (tlsModeTransporter, error) {
	return &tlsTransport{Conn: conn, reliable: r}, nil
}

// tlsTransport implements TLSModeTransporter.
type tlsTransport struct {
	net.Conn
	reliable *reliableTransport
}

// ReadPacket will try to read a packet from the underlying conn, and hand it to reliableTransport for processing.
func (t *tlsTransport) ReadPacket() (*packet, error) {
	panicIfTrue(t.Conn == nil, "nil Conn in tlsTransport")
	buf, err := readPacket(t.Conn)
	if err != nil {
		return nil, err
	}
	var p *packet
	// TODO(ainghazal): can delegate the rest of the method to reliableTransport
	if p, err = parsePacketFromBytes(buf); err != nil {
		return nil, err
	}
	if p.isACK() {
		t.reliable.processACK(p)
		return nil, nil
	}
	if t.reliable.isPacketTooFar(p) {
		// drop
		logger.Warnf("Packet too far: %v", p.id)
		return nil, nil
	}
	if dup, err := t.reliable.isDuplicatedPacket(p); dup || err != nil {
		// drop
		if err != nil {
			logger.Warnf("Error comparing packets: %v", err)
		} else {
			logger.Warnf("Dup: %v", p.id)
		}
		return nil, nil
	}
	t.reliable.TrackIncomingPacket(p)
	return p, nil
}

// WritePacket writes a packet to the underlying conn. It expect the opcode of
// the packet and a byte array containing the serialized data. It returns an
// error if the write did not succeed.
func (t *tlsTransport) WritePacket(opcodeKeyID uint8, data []byte) error {
	panicIfTrue(t.reliable.session == nil, "tlsTansport initialized with nil session")
	p := newPacketFromPayload(opcodeKeyID, 0, data)
	id, err := t.reliable.session.LocalPacketID()
	if err != nil {
		return err
	}
	p.id = id
	p.localSessionID = t.reliable.session.LocalSessionID
	payload := p.Bytes()
	out := maybeAddSizeFrame(t.Conn, payload)
	_, err = t.Conn.Write(out)
	return err
}

var _ tlsModeTransporter = &tlsTransport{} // Ensure that we implement TLSModelTransporter

// controlChannelTLSConn implements net.Conn, and is passed to the tls.Client to perform a
// TLS Handshake over OpenVPN control packets.
type controlChannelTLSConn struct {
	conn      net.Conn
	reliable  *reliableTransport
	transport tlsModeTransporter
	// we need to buffer reads because the tls records request less than
	// the payload we receive.
	bufReader *bytes.Buffer

	// for testing
	skipReadLoop bool
	skipACK      bool
}

// newControlChannelTLSConn returns a controlChannelTLSConn. It requires the on-the-wire
// net.Conn that will be used underneath, and a configured session. It returns
// also an error if the operation cannot be completed.
func newControlChannelTLSConn(conn net.Conn, r *reliableTransport) (*controlChannelTLSConn, error) {
	transport, err := newTLSModeTransport(conn, r)
	if err != nil {
		return &controlChannelTLSConn{}, err
	}
	buf := bytes.NewBuffer(nil)
	tlsConn := &controlChannelTLSConn{
		conn:      conn,
		reliable:  r,
		transport: transport,
		bufReader: buf,
	}
	return tlsConn, err
}

// Read over the control channel.  Returns number of read bytes, and an error
// if the operation could not be completed.
func (c *controlChannelTLSConn) Read(b []byte) (int, error) {
	panicIfTrue(c.reliable == nil, "controlChannelTLSConn: nil reliable (transport)")
	panicIfTrue(c.transport == nil, "controlChannelTLSConn: nil transport")
	panicIfTrue(c.reliable.session == nil, "controlChannelTLSConn: nil reliable.session")
	panicIfTrue(c.reliable.tlsQueueChan == nil, "controlChannelTLSConn: nil reliable.tlsQueueChan")

	var err error
	for {
		var p *packet

		switch len(c.reliable.tlsQueueChan) {
		// TODO should add a timeout here, perhaps
		case 0:
			p, err = c.transport.ReadPacket()
			if err != nil {
				logger.Errorf("cannot read packet: %v", err)
				break
			}
			if !c.skipReadLoop {
				continue
			}
		default:
			p = <-c.reliable.tlsQueueChan
		}

		if p == nil || err != nil {
			return 0, err
		}

		if !c.skipACK {
			if err := sendACKFn(c.conn, c.reliable, p.id); err != nil {
				return 0, err
			}
		}
		return writeAndReadFromBufferFn(c.bufReader, b, p.payload)
	}
	return 0, err
}

// writeAndReadPayloadFromBuffer writes a given payload to a buffered reader, and returns
// a read from that same buffered reader into the passed byte array. it returns both an integer
// denoting the amount of bytes read, and any error during the operation.
func writeAndReadFromBuffer(bb *bytes.Buffer, b []byte, payload []byte) (int, error) {
	panicIfTrue(bb == nil, "nil buffer")
	bb.Write(payload)
	return bb.Read(b)
}

var writeAndReadFromBufferFn = writeAndReadFromBuffer

// Write writes the given data to the tls connection.
func (c *controlChannelTLSConn) Write(b []byte) (int, error) {
	err := c.transport.WritePacket(uint8(pControlV1), b)
	if err != nil {
		logger.Errorf("tls write: %s", err.Error())
		return 0, err
	}
	return len(b), err
}

// Close closes the tls connection.
func (c *controlChannelTLSConn) Close() error {
	return c.conn.Close()
}

func (c *controlChannelTLSConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *controlChannelTLSConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *controlChannelTLSConn) SetDeadline(tt time.Time) error {
	return c.conn.SetDeadline(tt)
}

func (c *controlChannelTLSConn) SetReadDeadline(tt time.Time) error {
	return c.conn.SetReadDeadline(tt)
}

func (c *controlChannelTLSConn) SetWriteDeadline(tt time.Time) error {
	return c.conn.SetWriteDeadline(tt)
}

var _ net.Conn = &controlChannelTLSConn{} // Ensure that we implement net.Conn
