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
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	readTimeoutSeconds = 10
)

// one reader should be all we need
var sem = semaphore.NewWeighted(int64(1))

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
}

// read packets as they're available in the ackQueue and try to process them.
// if they're not consecutive, the processControlData function will insert them at the other
// side of the queue again
func (cw controlWrapper) runDataProcessLoop() {
	for data := range cw.ackQueue {
		go cw.processControlData(data)
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
		// we do.
		if isTCP(cw.control.Opts.Proto) {
			ok := sem.TryAcquire(1)
			if !ok {
				return 0, nil
			}
			if initialized {
				go cw.doReadTCP2(0)
			} else {
				go cw.doReadTCP(4098)
			}
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

/*
var debugCtr = 0

func decrCtr() {
	debugCtr -= 1
}
*/

func (cw controlWrapper) doReadTCP(size int) (int, error) {
	//debugCtr += 1
	//defer decrCtr()
	defer sem.Release(1)

	buf := make([]byte, size)
	// cw.control.conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeoutSeconds) * time.Second))

	// aha! this is the bug I think. there are several readers blocked on
	// read *before* initialization.
	//localCtr := debugCtr
	//log.Println("--> read?", size, "init:", initialized, localCtr)

	n, err := cw.control.conn.Read(buf)
	if err != nil {
		log.Println("read error:", err.Error())
		goto end
	}
	//log.Println("--> got", n, "(init:", initialized, ")", localCtr)
	if n != 0 {
		b := buf[:n]
		// expected len
		e := sizeFromHeader(b)
		cur := n - 2
		if cur > e {
			// if we get more, discard
			tmp := b
			b = tmp[:e+2]
			r := tmp[e+2:]
			log.Println("more! now:", len(b), e+2)
			log.Println("remaining:", len(r))
			log.Println("new?", sizeFromHeader(r))

		} else if cur < e {
			// if we got less, we will not leave this place without
			// waiting for what is ours.
			for i := 0; i < 10; i++ {
				missing := e - cur
				if missing > 0 {
					//log.Println("need more:", missing)
					m := make([]byte, e-n)
					cw.control.conn.SetReadDeadline(time.Now().Add(time.Duration(5) * time.Second))

					nn, err := cw.control.conn.Read(m)
					if err != nil {
						goto end
					}
					b = append(b, m...)
					n = n + nn
				}
			}
		}
		// all good, process this
		cw.ackQueue <- b
		return n, nil
	}
end:
	return 0, nil
}

// TODO cleanup and merge with the function above
func (cw controlWrapper) doReadTCP2(size int) (int, error) {
	defer sem.Release(1)

	bl := make([]byte, 2)
	cw.control.conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeoutSeconds) * time.Second))
	_, err := cw.control.conn.Read(bl)
	if err != nil {
		log.Println("read error:", err.Error())
		return 2, err
	}
	//fmt.Println(hex.Dump(bl))
	e := int(binary.BigEndian.Uint16(bl))

	b := make([]byte, e)
	cw.control.conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeoutSeconds) * time.Second))

	n, err := cw.control.conn.Read(b)
	if err != nil {
		log.Println("read error:", err.Error())
		return n, err
	}
	//log.Println("--> got", n)
	//log.Println("--> exp", e)
	cur := n
	if cur == e {
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
				log.Printf("WARN packet len mismatch: expected %d, got %d\n", l, len(d))
			}
			log.Println("dropping", len(d))
			return
		}
	}
	if len(d) == 0 {
		return
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
