package vpn

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// initTLS is part of the control channel. It initializes the TLS options with
// certificate, key and ca from control.Opts, and it performs
// a handshake wrapped as payloads in the control channel.
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

	bufReader := bytes.NewBuffer(nil)
	ackq := make(chan []byte, 50)
	cw := controlWrapper{control: c, bufReader: bufReader, ackQueue: ackq}
	go cw.dataProcessLoop()

	tlsConn := tls.Client(cw, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("%s %w", ErrBadHandshake, err)
	}
	log.Println("Handshake done!")
	c.tls = net.Conn(tlsConn)
	return nil
}

// controlWrapper allows TLS Handshake to send its records
// as part of one openvpn CONTROL_V1 packet. It reads from the net.Conn in the
// wrapped control struct, and it writes to control.tlsIn buffered channel.
type controlWrapper struct {
	control   *control
	bufReader *bytes.Buffer
	ackQueue  chan []byte
	rbmu      sync.Mutex
}

func (cw controlWrapper) Write(b []byte) (n int, err error) {
	return cw.control.sendControlV1(b)
}

func (cw controlWrapper) isConsecutive(b []byte) bool {
	cw.control.ackmu.Lock()
	defer cw.control.ackmu.Unlock()
	pid, _, _ := cw.control.readControl(b)
	return int(pid)-cw.control.lastAck == 1
}

func (cw controlWrapper) dataProcessLoop() {
	for {
		select {
		case data := <-cw.ackQueue:
			go cw.processControlData(data)
		}
	}
}

func (cw controlWrapper) processControlData(d []byte) {
	cw.rbmu.Lock()
	defer cw.rbmu.Unlock()
	if isTCP(cw.control.Opts.Proto) {
		// TCP size framing
		l := int(binary.BigEndian.Uint16(d[:2]))
		d = d[2:]
		if len(d) != l {
			// TODO get a more elegant verbose flag
			// BUG: OpenVPN packets received over a TCP stream sometimes contain more data than announced in the size header.
			// (see controlWrapper.Read method below)
			// this is probably related to being sloppy on Reads, but for now is "cheap" to just discard
			// the reads that do not match the size header.
			// i've tried buffered reads, but it stalls.
			// what does the reference implementation do?
			if os.Getenv("DEBUG") == "1" {
				log.Printf("WARN packet len mismatch: expected %d, got %d\n", l, len(d))
			}
			// dropping it is a waste, but most viable solution I've found so far
			return
		}
	}
	op := d[0] >> 3
	if op == byte(pACKV1) {
		// might want to do something with this ACK
		log.Println("Received ACK")
		return
	}
	// this is *only* a DATA_V1 for now
	if isDataOpcode(op) {
		cw.control.dataQueue <- d
		return
	} else if op != byte(pControlV1) {
		log.Printf("Received unknown opcode: %v\n", op)
		return
	}
	if cw.isConsecutive(d) {
		pid, _, payload := cw.control.readControl(d)
		cw.control.sendAck(pid)
		cw.control.tlsIn <- payload
	} else {
		cw.ackQueue <- d
	}
}

func (cw controlWrapper) Read(b []byte) (int, error) {
	cw.rbmu.Lock()
	if len(b) == 0 {
		return 0, nil
	}
	select {
	case p := <-cw.control.tlsIn:
		cw.bufReader.Write(p)
		cw.rbmu.Unlock()
		return cw.bufReader.Read(b)
	case <-time.After(10 * time.Millisecond):
		break
	}
	go func() {
		defer cw.rbmu.Unlock()
		// FIXME this works nicely for udp, but breaks for tcp
		// I've tried with a bufio.Reader and peeking the size header, but to no avail.
		buf := make([]byte, 4096)
		n, _ := cw.control.conn.Read(buf)
		if n != 0 {
			cw.ackQueue <- buf[:n]
		}
	}()
	return 0, nil
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
