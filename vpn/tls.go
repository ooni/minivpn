package vpn

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// initTLS is part of the control channel
func (c *control) initTLS() bool {

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
	if c.Auth.Cert != "" {
		ca := x509.NewCertPool()
		caData, err := ioutil.ReadFile(c.Auth.Ca)
		if err != nil {
			log.Fatal(err)
		}
		ca.AppendCertsFromPEM(caData)
		cert, err := tls.LoadX509KeyPair(c.Auth.Cert, c.Auth.Key)
		if err != nil {
			log.Fatal(err)
		}
		tlsConf.RootCAs = ca
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	bufReader := bytes.NewBuffer(nil)
	udp := controlWrapper{control: c, bufReader: bufReader}

	tlsConn := tls.Client(udp, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		log.Println("ERROR Invalid handshake:")
		log.Fatal(err)
	}
	log.Println("Handshake done!")
	c.tls = net.Conn(tlsConn)
	return true
}

// this wrapper allows TLS Handshake to send its records
// as part of one openvpn CONTROL_V1 packet

type controlWrapper struct {
	control   *control
	bufReader *bytes.Buffer
	mu        sync.Mutex
}

func (cw controlWrapper) Write(b []byte) (n int, err error) {
	return cw.control.sendControlV1(b)
}

func (cw controlWrapper) Read(b []byte) (int, error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	var data []byte
	if len(b) == 0 {
		return 0, nil
	}
	// quick hack: w/o this wait, we arrive here while some other data
	// is being processed going to the tlsIn queue. use a proper sync
	// primitive instead! -- interestingly, this one wait seems to be needed
	// even with the delayed out-of-order hack below.
	time.Sleep(50 * time.Millisecond)

	if len(cw.control.tlsIn) != 0 {
		var p []byte
		p = <-cw.control.tlsIn
		cw.bufReader.Write(p)
		return cw.bufReader.Read(b)
	}
	go func() {
		buf := make([]byte, len(b))
		numBytes, _ := cw.control.conn.Read(buf)
		data = buf[:numBytes]

		if numBytes == 0 {
			return
		}

		// log.Println("Processing", numBytes, "bytes...")
		op := data[0] >> 3
		if op == byte(P_ACK_V1) {
			// XXX might want to do something with this ACK
			log.Println("Received ACK")
			return
		}
		// this is *only* a DATA_V1 for now
		if isDataOpcode(op) {
			cw.control.dataQueue <- data
			return
		} else if op != byte(P_CONTROL_V1) {
			// FIXME need to pass this to data channel to decrypt...
			log.Printf("Received unknown opcode: %v\n", op)
			log.Printf("len: %d\n", len(data))
			log.Printf("data: %v\n", data)
			log.Fatal("Unknown Opcode")
		}

		pid, _, payload := cw.control.readControl(data)
		cw.control.sendAck(pid)
		// same hack that in ACK'ing on the control channel.
		// instead of the ugly hack of waiting, it'd be more elegant to
		// find the right sync primitive to avoid this.
		// part of the problem is that I don't quite understand why some times
		// something enters the tls queue that is not what's expected for a tls
		// record.
		if int(pid)-cw.control.lastAck > 1 {
			go func() {
				log.Println("DEBUG delay in TLS buffer...")
				time.Sleep(time.Second)
				cw.control.tlsIn <- payload
			}()
		} else {
			cw.control.tlsIn <- payload
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
