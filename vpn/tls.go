package vpn

//
// TLS initialization and read/write wrappers
//

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"
)

const (
	readTimeoutSeconds = 10
)

var (
	// ErrBadHandshake is returned when the OpenVPN handshake failed.
	ErrBadHandshake = errors.New("handshake failure")
)

// initTLS is part of the control channel. It initializes the TLS options with
// certificate, key and ca from control.Opts, and it performs
// a handshake wrapped as payloads in the control channel.

// TODO(ainghazal): add checks for valid certificates etc on config time.

func (c *control) initTLS() error {
	max := tls.VersionTLS13

	if c.Opts.TLSMaxVer == "1.2" {
		max = tls.VersionTLS12
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         uint16(max),
	}

	// we assume a non-empty cert means we've got also a valid ca and key,
	// but should check
	if c.Opts.Cert != "" {
		ca := x509.NewCertPool()
		caData, err := ioutil.ReadFile(c.Opts.Ca)
		if err != nil {
			return fmt.Errorf("%s %w", ErrBadCA, err)
		}
		ca.AppendCertsFromPEM(caData)
		cert, err := tls.LoadX509KeyPair(c.Opts.Cert, c.Opts.Key)
		if err != nil {
			return fmt.Errorf("%s %w", ErrBadKeypair, err)
		}
		tlsConf.RootCAs = ca
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	log.Println("TLS HANDSHAKE ~~~~~~~~~~~~~~~~~~~~ ")
	log.Println("local pid:", c.localPID)

	s := &session{sessionID: c.SessionID, localPID: c.localPID, control: c}

	if isDebugOLD() {
		// old implementation ------------------------

		bufReader := bytes.NewBuffer(nil)
		ackq := make(chan []byte, 50)
		cw := controlWrapper{control: c, bufReader: bufReader, ackQueue: ackq}

		// start the data processing loop: it consumes packets read by the
		// underlying conn and queued there to be processed.
		go cw.runDataProcessLoop()

		tlsConn := tls.Client(cw, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("%s %w", ErrBadHandshake, err)
		}
		c.tls = net.Conn(tlsConn)
	} else {
		// new transport

		tlsConn, err := NewTLSConn(c.conn, s)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrBadHandshake, err)
		}
		tls := tls.Client(tlsConn, tlsConf)
		if err := tls.Handshake(); err != nil {
			return fmt.Errorf("%w: %s", ErrBadHandshake, err)
		}
	}

	log.Println("Handshake done!")
	return nil
}

// ----- all code below must die --------------------------------------------------

// controlWrapper allows TLS Handshake to send its records
// as part of one openvpn CONTROL_V1 packet. It reads from the net.Conn in the
// wrapped control struct, and it writes to control.tlsIn buffered channel.
type controlWrapper struct {
	control   *control
	bufReader *bytes.Buffer
	ackQueue  chan []byte
}

// read packets as they're available in the ackQueue and try to process them.
// if they're not consecutive, the processControlData function will insert them at the other
// side of the queue again
func (cw controlWrapper) runDataProcessLoop() {
	for data := range cw.ackQueue {
		go cw.processControlData(data)
	}
}

// Write is simple: we just delegate wriites to the control channel, that packetizes and writes
// to the tunnel conn.
func (cw controlWrapper) Write(b []byte) (n int, err error) {
	return cw.control.sendControlV1(b)
}

func (cw controlWrapper) Read(b []byte) (int, error) {
	if !isDebugOLD() {
		log.Println("cw read...", len(b))
	}

	if len(b) == 0 || cw.control.closed {
		return 0, nil
	}

	// first we try to read data from incoming tls records
	// if nothing there, we do a read in the background
	select {
	case p := <-cw.control.tlsIn:
		cw.bufReader.Write(p)
		log.Printf("tls: %d bytes\n", len(p))
		fmt.Println(hex.Dump(p))
		return cw.bufReader.Read(b)
	// again, this is something empirical, but if I don't give some time
	// to the tlsIn queue to catch up we don't move forward. code smell:
	// data races as a feature.
	case <-time.After(10 * time.Millisecond):
		// we queue the read, it will be processed by the data/control channels.
		// we don't want to acknowledge that we did read anything (i'm
		// not fully clear about why, but empirically it does stall if
		// we do.
		if isTCP(cw.control.Opts.Proto) {
			ok := rcvSem.TryAcquire(1)
			if !ok {
				return 0, nil
			}
			go cw.doReadTCP(0)
		} else {
			go cw.doReadUDP(4096)
		}
		break
	}
	// read? what read you say?
	return 0, nil

}

func (cw controlWrapper) doReadUDP(size int) {
	buf := make([]byte, size)
	n, _ := cw.control.conn.Read(buf)
	if n != 0 {
		cw.ackQueue <- buf[:n]
	}
}

func (cw controlWrapper) doReadTCP(size int) (int, error) {
	defer rcvSem.Release(1)
	log.Println("--> read tcp")

	/* read len-delimited tcp buffer -------------- */
	bl := make([]byte, 2)
	_, err := cw.control.conn.Read(bl)
	if err != nil {
		log.Println("read error:", err.Error())
		return 2, err
	}
	e := int(binary.BigEndian.Uint16(bl))
	b := make([]byte, e)
	n, err := cw.control.conn.Read(b)
	if err != nil {
		log.Println("read error:", err.Error())
		return n, err
	}
	//cur := n
	if n == e {
		cw.ackQueue <- append(bl, b...)
		return n + 2, nil
	}

	return 0, nil
}

func (cw controlWrapper) processControlData(d []byte) {
	if len(d) == 0 {
		return
	}
	if isTCP(cw.control.Opts.Proto) {
		// TCP size framing check
		l := sizeFromHeader(d)
		d = d[2:]
		if len(d) != l {
			if isDebug() {
				log.Printf("bad len: expected %d, got %d\n", l, len(d))
			}
			log.Println("dropping", len(d))
			return
		}
	}
	if len(d) == 0 {
		return
	}

	p := newPacketFromBytes(d)
	if p.isACK() {
		log.Println("Received ACK; len:", len(d))
		fmt.Println(hex.Dump(d))
		return
	}
	if p.isData() {
		cw.control.dataQueue <- d
		return
	}
	if !p.isControlV1() {
		log.Printf("WARN dropping unknown opcode: %v\n", p.opcode)
		return
	}

	// parse it
	p = newControlPacketFromBytes(d)
	if isNextPacket(p) {
		log.Println("ack:", p.id)
		cw.control.sendAck(p.id)
		cw.control.tlsIn <- p.payload
	} else {
		// TODO add a delay here to avoid waste?
		log.Println("Out of order: re-queue. got", p.id, "expected:", lastAck+1)
		cw.ackQueue <- d
	}
}

func (cw controlWrapper) LocalAddr() net.Addr {
	return cw.control.conn.LocalAddr()
}

func (cw controlWrapper) RemoteAddr() net.Addr {
	return cw.control.conn.RemoteAddr()
}

func (cw controlWrapper) SetDeadline(t time.Time) error {
	return cw.control.conn.SetDeadline(t)
}

func (cw controlWrapper) SetReadDeadline(t time.Time) error {
	return cw.control.conn.SetReadDeadline(t)
}

func (cw controlWrapper) SetWriteDeadline(t time.Time) error {
	return cw.control.conn.SetWriteDeadline(t)
}

func (cw controlWrapper) Close() error {
	return cw.control.conn.Close()
}
