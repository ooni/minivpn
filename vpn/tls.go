package vpn

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
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

// TODO add checks for valid certificates etc on config time.

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

	// start the data processing loop: it consumes packets read by the
	// underlying conn and queued there to be processed.
	go cw.runDataProcessLoop()

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

// read packets as they're available in the ackQueue and try to process them.
// if they're not consecutive, the processControlData function will insert them at the other
// side of the queue again
func (cw controlWrapper) runDataProcessLoop() {
	for {
		select {
		case data := <-cw.ackQueue:
			go cw.processControlData(data)
		}
	}
}

// we need to be able to perform a small reordering on our side - I believe
// OpenVPN does something quite similar.
func (cw controlWrapper) isConsecutive(b []byte) bool {
	cw.control.ackmu.Lock()
	defer cw.control.ackmu.Unlock()
	pid, _, _ := cw.control.readControl(b)
	return int(pid)-cw.control.lastAck == 1
}

// Write is simple: we just delegate wriites to the control channel, that packetizes and writes
// to the tunnel conn.
func (cw controlWrapper) Write(b []byte) (n int, err error) {
	return cw.control.sendControlV1(b)
}

func (cw controlWrapper) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// first we try to read data from incoming tls records
	// if nothing there, we do a read in the background

	select {
	case p := <-cw.control.tlsIn:
		cw.bufReader.Write(p)
		return cw.bufReader.Read(b)
	// again, this is something empirical, but if I don't give some time
	// to the tlsIn queue to catch up we don't move forward. code smell:
	// data races as a feature.
	case <-time.After(10 * time.Millisecond):
		// we queue the read, it will be processed by the data/control channels.
		// we don't want to acknowledge that we did read anything (i'm
		// not fully clear about why, but empirically it does stall if
		// we do. I suspect this might lie behind some of the
		// bigger inefficiencies that plague this implementation).
		go cw.doRead(4096)
		break
	}
	// read? what read you say?
	return 0, nil

}

// TODO reset readline every time that we read?
func (cw controlWrapper) doRead(size int) (int, error) {
	cw.rbmu.Lock()
	defer cw.rbmu.Unlock()

	buf := make([]byte, size)
	n, err := cw.control.conn.Read(buf)
	if err != nil {
		log.Println("read error:", err.Error())
		return 0, err
	}
	log.Println("--> got", n)
	if n != 0 {
		b := buf[:n]
		// expected lengtht
		e := lenFromHeader(b)
		if n-2 > e {
			// if we get more, discard
			b = b[:e+2]
			log.Println("more! now:", len(b), e+2)
		} else if n-2 < e {
			// if we got less, we will not leave this place without
			// waiting for what is ours.
			for {
				if n-2 == e {
					break
				}
				m := make([]byte, e-n)
				nn, _ := cw.control.conn.Read(m)
				b = append(b, m...)
				n = n + nn
			}
		}
		// all good, process this
		cw.ackQueue <- b
		return n, nil
	}
	return 0, nil
}

func (cw controlWrapper) processControlData(d []byte) {
	if len(d) == 0 {
		return
	}
	if isTCP(cw.control.Opts.Proto) {
		// TCP size framing
		bl := d[:2]
		l := int(binary.BigEndian.Uint16(bl))
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
				fmt.Println(hex.Dump(bl))
			}
			log.Println("dropping", len(d))
			return
		}
	}
	if len(d) == 0 {
		return
	}
	//log.Println(">> process...")
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
		log.Printf("WARN dropping unknown opcode: %v\n", op)
		return
	}
	if cw.isConsecutive(d) {
		pid, _, payload := cw.control.readControl(d)
		cw.control.sendAck(pid)
		cw.control.tlsIn <- payload
	} else {
		// TODO add a delay here to avoid waste?
		log.Println("Out of order: re-queue...")
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
