package vpn

//
// Transports for OpenVPN over TCP and over UDP.
// This file includes:
// 1. Methods for reading packets from the wire
// 2. A TLS transport that reads and writes TLS records as part of control packets.
//

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
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

// tlsModeTransporter is a transport for OpenVPN in TLS mode.
//
// See https://openvpn.net/community-resources/openvpn-protocol/ for documentation
// on the protocol used by OpenVPN on the wire.
type tlsModeTransporter interface {
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

// newTLSModeTransport creates a new TLSModeTransporter using the given net.Conn.
func newTLSModeTransport(conn net.Conn, s *session) (tlsModeTransporter, error) {
	return &tlsTransport{Conn: conn, session: s}, nil
}

// tlsTransport implements TLSModeTransporter.
type tlsTransport struct {
	net.Conn
	session *session
}

// ReadPacket returns a packet reading from the underlying conn, and an error
// if the read did not succeed.
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
		//TODO: think about it
		/*if err := sendACKFn(t.Conn, t.session, p.id); err != nil {
			return &packet{}, err
		}*/
		t.session.lastACK++
		logger.Warn("tls: got ACK (ignored)")
		return &packet{}, nil
	}
	return p, nil
}

// WritePacket writes a packet to the underlying conn. It expect the opcode of the packet and a byte array containing the serialized data. It returns an error if the write did not succeed.
func (t *tlsTransport) WritePacket(opcodeKeyID uint8, data []byte) error {
	if t.session == nil {
		return fmt.Errorf("%w:%s", errBadInput, "tlsTransport badly initialized")

	}
	id, err := t.session.LocalPacketID()
	fmt.Println(id)
	if err != nil {
		return err
	}
	p := newPacketFromPayload(opcodeKeyID, 0, data)
	p.localSessionID = t.session.LocalSessionID
	p.id = id

	out := append([]byte{0x20}, t.session.LocalSessionID[:]...)

	ackBytes := []byte{0, 0, 0, 0, 1}
	timestamp := uint32(time.Now().Unix())
	timeBytes := binary.BigEndian.AppendUint32(nil, timestamp)
	packetIDBytes := binary.BigEndian.AppendUint32(nil, uint32(p.id))

	secret, _ := hex.DecodeString(secretKey)
	hmacHash := hmac.New(sha1.New, secret[:20])
	hmacHash.Write(packetIDBytes)
	hmacHash.Write(timeBytes)
	hmacHash.Write(out)
	hmacHash.Write(ackBytes)
	hmacHash.Write(data)
	hmacResult := hmacHash.Sum(nil)
	out = append(out, hmacResult...)

	out = append(out, packetIDBytes...)
	out = append(out, timeBytes...)
	out = append(out, ackBytes...)
	out = append(out, data...)

	out = maybeAddSizeFrame(t.Conn, out)

	logger.Debug(fmt.Sprintln("tls write:", len(out)))
	logger.Debug(fmt.Sprintln(hex.Dump(out)))

	_, err = t.Conn.Write(out)
	return err
}

var _ tlsModeTransporter = &tlsTransport{} // Ensure that we implement TLSModelTransporter

// controlChannelTLSConn implements net.Conn, and is passed to the tls.Client to perform a
// TLS Handshake over OpenVPN control packets.
type controlChannelTLSConn struct {
	conn      net.Conn
	session   *session
	transport tlsModeTransporter
	// we need to buffer reads because the tls records request less than
	// the payload we receive.
	bufReader *bytes.Buffer

	doReadFromConnFn  func(*controlChannelTLSConn, []byte) (bool, int, error)
	doReadFromQueueFn func(*controlChannelTLSConn, []byte) (bool, int, error)
}

// newControlChannelTLSConn returns a controlChannelTLSConn. It requires the on-the-wire
// net.Conn that will be used underneath, and a configured session. It returns
// also an error if the operation cannot be completed.
func newControlChannelTLSConn(conn net.Conn, s *session) (*controlChannelTLSConn, error) {
	transport, err := newTLSModeTransport(conn, s)
	if err != nil {
		return &controlChannelTLSConn{}, err
	}
	buf := bytes.NewBuffer(nil)
	tlsConn := &controlChannelTLSConn{
		conn:      conn,
		session:   s,
		transport: transport,
		bufReader: buf,
	}
	tlsConn.doReadFromConnFn = doReadFromConn
	tlsConn.doReadFromQueueFn = doReadFromQueue
	return tlsConn, err
}

// Read over the control channel. This method implements the reliability layer:
// it retries reads until the _next_ packet is received (according to the
// packetID). Returns also an error if the operation cannot be completed.
func (c *controlChannelTLSConn) Read(b []byte) (int, error) {
	if c.session == nil || c.session.ackQueue == nil {
		return 0, fmt.Errorf("%w: %s", errBadInput, "bad session in TLSConn.Read()")
	}
	for {
		switch len(c.session.ackQueue) {
		case 0:
			ok, n, err := c.doReadFromConnFn(c, b)
			if ok {
				return n, err
			}
		default:
			ok, n, err := c.doReadFromQueueFn(c, b)
			if ok {
				return n, err
			}
		}
	}
}

func doReadFromConn(c *controlChannelTLSConn, b []byte) (bool, int, error) {
	p, err := c.doRead()

	if err != nil {
		return true, 0, err
	}
	switch c.canRead(p) {
	case true:
		if err := sendACKFn(c.conn, c.session, p.id); err != nil {
			return true, 0, err
		}
		n, err := writeAndReadFromBufferFn(c.bufReader, b, p.payload)
		return true, n, err
	case false:
		if p != nil {
			c.session.ackQueue <- p
		}
	}

	return false, 0, nil
}

func doReadFromQueue(c *controlChannelTLSConn, b []byte) (bool, int, error) {
	for p := range c.session.ackQueue {
		if c.canRead(p) {
			if err := sendACKFn(c.conn, c.session, p.id); err != nil {
				return true, 0, err
			}
			n, err := writeAndReadFromBufferFn(c.bufReader, b, p.payload)
			return true, n, err
		} else {
			c.session.ackQueue <- p
			return doReadFromConn(c, b)
		}
	}
	return false, 0, nil
}

// doRead() calls ReadPacket() in the underlying transport implementation. It
// returns a packet and an error.
func (c *controlChannelTLSConn) doRead() (*packet, error) {
	if c.transport == nil {
		return nil, fmt.Errorf("%w:%s", errBadInput, "tlsConn is missing transport")

	}
	return c.transport.ReadPacket()
}

// canRead returns true if the packet is not nil and its packetID is the next
// integer in the expected sequence; returns false otherwise.
func (c *controlChannelTLSConn) canRead(p *packet) bool {
	return p != nil && c.session.isNextPacket(p)
}

// writeAndReadPayloadFromBuffer writes a given payload to a buffered reader, and returns
// a read from that same buffered reader into the passed byte array. it returns both an integer
// denoting the amount of bytes read, and any error during the operation.
func writeAndReadFromBuffer(bb *bytes.Buffer, b []byte, payload []byte) (int, error) {
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
