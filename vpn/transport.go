package vpn

//
// Transports for OpenVPN over TCP and over UDP.
//

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
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

// NewTLSModeTransport creates a new TLSModeTransport using the given net.Conn.
func NewTLSModeTransport(conn net.Conn, s *session) (TLSModeTransport, error) {
	switch network := conn.LocalAddr().Network(); network {
	case "tcp", "tcp4", "tcp6":
		return &tlsModeTransportTCP{Conn: conn, session: s}, nil
	case "udp", "udp4", "udp6":
		return &tlsModeTransportUDP{Conn: conn, session: s}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrBadConnNetwork, network)
	}
}

// transportParsePacket is a convenience function for parsing packets.
// TODO(ainghazal): this belongs to the muxer
// TODO move to session for now?
func transportParsePacket(buff []byte) (uint8, []byte, error) {
	if len(buff) < 1 {
		return 0, nil, ErrPacketTooShort
	}
	opcodeKeyID := buff[0]
	buff = buff[1:]
	fmt.Println(hex.Dump(buff))
	return opcodeKeyID, buff, nil
}

// tlsModeTransportUDP implements TLSModeTransport for UDP.
type tlsModeTransportUDP struct {
	net.Conn
	session *session
}

func (txp *tlsModeTransportUDP) ReadPacket() (*packet, error) {
	const enough = 1 << 17
	buff := make([]byte, enough)
	count, err := txp.Conn.Read(buff)
	if err != nil {
		return nil, err
	}
	buff = buff[:count]

	p := newPacketFromBytes(buff)
	return p, nil
}

func (txp *tlsModeTransportUDP) WritePacket(opcodeKeyID uint8, data []byte) error {
	log.Println("write packet udp")

	var out bytes.Buffer
	out.WriteByte(opcodeKeyID)
	out.Write(data)
	_, err := txp.Conn.Write(out.Bytes())
	return err
}

// tlsModeTransportTCP implements TLSModeTransport for TCP.
type tlsModeTransportTCP struct {
	net.Conn
	session *session
}

func (txp *tlsModeTransportTCP) ReadPacket() (*packet, error) {
	log.Println("read tcp...")
	lenbuff := make([]byte, 2)
	if _, err := io.ReadFull(txp.Conn, lenbuff); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenbuff)
	log.Println("debug: len", length)

	buff := make([]byte, length)
	if _, err := io.ReadFull(txp.Conn, buff); err != nil {
		return nil, err
	}
	p := newPacketFromBytes(buff)
	if p.isControlV1() {
		p = parseControlPacket(p)
	}
	log.Println("Received packet id", p.id)

	if p.isACK() {
		log.Println("ACK, should skip...")
		return nil, nil
	}
	return p, nil
}

func (txp *tlsModeTransportTCP) WritePacket(opcodeKeyID uint8, data []byte) error {
	log.Println("write control packet tcp")

	// XXX dump from packet instead??
	payload, err := txp.session.makeControlPayload(data)
	if err != nil {
		log.Println("error writing:", err.Error())
		return err
	}

	length := make([]byte, 2)
	// XXX watch out, I had an off-by-one bug!! the len is the payload + the opcode!!
	binary.BigEndian.PutUint16(length, uint16(len(payload)+1))

	var out bytes.Buffer
	out.Write(length)
	out.WriteByte(opcodeKeyID)
	out.Write(payload)

	log.Println("tls write:", len(out.Bytes()))
	fmt.Println(hex.Dump(out.Bytes()))
	_, err = txp.Conn.Write(out.Bytes())
	return err
}

// TODO(ainghazal): this is an attempt to extract what mutable state do we need to pass around
// for being able to write/read control packets. these fields were in control struct before.
// TODO this state goes into --> dataChannelState
type session struct {
	sessionID []byte
	localPID  uint32

	// TODO refactor: temporary workaround to be able to send acks during the handshake
	control *control
}

func (s *session) localPIDAsBytes() []byte {
	pid := make([]byte, 4)
	binary.BigEndian.PutUint32(pid, s.localPID)
	return pid
}

func (s *session) makeControlPayload(data []byte) ([]byte, error) {
	var out bytes.Buffer
	out.Write(s.sessionID)
	out.WriteByte(0x00)
	out.Write(s.localPIDAsBytes())
	out.Write(data)
	// TODO(ainghazal): protect this increment
	s.localPID++
	return out.Bytes(), nil
}

// TLSConn implements net.Conn, and is passed to the tls.Client to perform a
// TLS Handshake over OpenVPN control packets.
type TLSConn struct {
	tlsTr     TLSModeTransport
	conn      net.Conn
	session   *session
	bufReader *bytes.Buffer
}

func (t *TLSConn) Read(b []byte) (int, error) {
	// XXX this is basically the reliability layer. retry until next packet is received.
	pa := &packet{}
	for {
		if len(ackQueue) != 0 {
			log.Printf("queued: %d packets", len(ackQueue))
			for p := range ackQueue {
				log.Println("trying packet:", p.id)
				if isNextPacket(p) {
					pa = p
					break
				} else {
					ackQueue <- p
					goto read
				}
			}
		}

	read:
		log.Println("read packet")
		p, err := t.tlsTr.ReadPacket()
		if err != nil {
			log.Println("got error:", err.Error())
			return 0, err
		}
		if isNextPacket(p) {
			pa = p
			break
		} else {
			log.Println("queue")
			ackQueue <- p
			continue
		}

	}
	if isNextPacket(pa) {
		t.session.control.sendAck(pa.id)
	}
	t.bufReader.Write(pa.payload)
	return t.bufReader.Read(b)
}

func (t *TLSConn) Write(b []byte) (int, error) {
	opCode := byte(pControlV1 << 3)
	err := t.tlsTr.WritePacket(opCode, b)
	if err != nil {
		log.Println("ERROR write:", err.Error())
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

func NewTLSConn(conn net.Conn, s *session) (*TLSConn, error) {
	tlsTr, err := NewTLSModeTransport(conn, s)
	bufReader := bytes.NewBuffer(nil)
	tlsConn := &TLSConn{tlsTr, conn, s, bufReader}
	return tlsConn, err

}

// some convenience functions while debugging handshake, move to packet.go?

func dumpOpcodeInfo(op uint8) {
	log.Printf(">> opcode: %d. ack: %v, data: %v, control: %v\n", op, isACK(op), isDataOpcode(op), isControlOpcode(op))
}

func isControlV1(op uint8) bool {
	return op == byte(pControlV1)
}

func isACK(op uint8) bool {
	return op == byte(pACKV1)
}
