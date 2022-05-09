package vpn

// TODO move to control.go
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

// InitTLS performs a TLS handshake over the control channel. It is the fourth
// step in an OpenVPN connection (out of five).
// TODO(ainghazal): add checks for valid certificates etc on config time.
func (c *control) InitTLS(conn net.Conn, session *session) (net.Conn, error) {
	max := tls.VersionTLS13

	if c.Options().TLSMaxVer == "1.2" {
		max = tls.VersionTLS12
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         uint16(max),
	}

	// TODO make cert checks a pre-run check.
	// we assume a non-empty cert means we've got also a valid ca and key,
	// but should check
	if c.Options().Cert != "" {
		ca := x509.NewCertPool()
		caData, err := ioutil.ReadFile(c.Options().Ca)
		if err != nil {
			return nil, fmt.Errorf("%s %w", ErrBadCA, err)
		}
		ca.AppendCertsFromPEM(caData)
		cert, err := tls.LoadX509KeyPair(c.Options().Cert, c.Options().Key)
		if err != nil {
			return nil, fmt.Errorf("%s %w", ErrBadKeypair, err)
		}
		tlsConf.RootCAs = ca
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	tlsConn, err := NewTLSConn(conn, session)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadHandshake, err)
	}
	tlsClient := tls.Client(tlsConn, tlsConf)
	if err := tlsClient.Handshake(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadHandshake, err)
	}

	log.Println("TLS handshake done!")
	return net.Conn(tlsClient), nil
}
