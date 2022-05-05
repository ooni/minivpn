package vpn

//
// TLS initialization and read/write wrappers
//

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

const (
	readTimeoutSeconds = 10
)

var (
	// ErrBadHandshake is returned when the OpenVPN handshake failed.
	ErrBadHandshake = errors.New("handshake failure")
)

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

	// TODO: session must go to muxer
	s := &session{sessionID: c.SessionID, localPID: c.localPID, control: c}

	tlsConn, err := NewTLSConn(c.conn, s)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBadHandshake, err)
	}
	tls := tls.Client(tlsConn, tlsConf)
	if err := tls.Handshake(); err != nil {
		return fmt.Errorf("%w: %s", ErrBadHandshake, err)
	}

	// From now on, the communication over the control channel SHOULD happen
	// over this new net.Conn - it encrypts the contents written to it.
	c.tls = net.Conn(tls)

	log.Println("Handshake done!")
	return nil
}
