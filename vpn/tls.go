package vpn

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

// initTLS is part of the control channel. It initializes the TLS options with
// certificate, key and ca comings in the control.Auth struct, and it performs
// a handshake wrapped as payloads in the control channel.
func (c *control) initTLS() error {
	max := tls.VersionTLS12
	if os.Getenv("TLSv13") == "1" {
		max = tls.VersionTLS13
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		// I need to specify this for my test endpoint, for some reason doesn't know how to negotiate tls max.
		MaxVersion: uint16(max),
		//TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
		//CipherSuites: []uint16{
		//	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		//},
		//tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		//DHE-RSA-AES128-SHA
		//},
	}

	// we assume a non-empty cert means we've got also a valid ca and key,
	// but should check
	if c.Opts.Cert != "" {
		ca := x509.NewCertPool()
		caData, err := ioutil.ReadFile(c.Opts.Ca)
		if err != nil {
			return err
		}
		ca.AppendCertsFromPEM(caData)
		cert, err := tls.LoadX509KeyPair(c.Opts.Cert, c.Opts.Key)
		if err != nil {
			return err
		}
		tlsConf.RootCAs = ca
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	bufReader := bytes.NewBuffer(nil)
	ackq := make(chan []byte, 50)
	udp := controlWrapper{control: c, bufReader: bufReader, ackQueue: ackq}
	go udp.dataProcessLoop()

	tlsConn := tls.Client(udp, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return err
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
	op := d[0] >> 3
	if op == byte(P_ACK_V1) {
		// might want to do something with this ACK
		log.Println("Received ACK")
		return
	}
	// this is *only* a DATA_V1 for now
	if isDataOpcode(op) {
		cw.control.dataQueue <- d
		return
	} else if op != byte(P_CONTROL_V1) {
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
	if len(b) == 0 {
		return 0, nil
	}
	// TODO I have "avoided" the sleep by stuffing it as a select timeout
	// but I still don't understand why the results are so unstable
	// without it...
	// time.Sleep(50 * time.Millisecond)
	select {
	case p := <-cw.control.tlsIn:
		cw.bufReader.Write(p)
		return cw.bufReader.Read(b)
	case <-time.After(10 * time.Millisecond):
		break
	}
	go func() {
		// use a semaphore?
		// at times we're exhausting this poor conn guy...
		buf := make([]byte, 4096)
		numBytes, _ := cw.control.conn.Read(buf)
		if numBytes != 0 {
			cw.ackQueue <- buf[:numBytes]
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
