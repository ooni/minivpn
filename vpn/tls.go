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
	"net"
)

const (
	readTimeoutSeconds = 10
)

var (
	// ErrBadTLSHandshake is returned when the OpenVPN handshake failed.
	ErrBadTLSHandshake = errors.New("handshake failure")
	// ErrBadCA is returned when the CA file cannot be found or is not valid.
	ErrBadCA = "bad ca conf"
	// ErrBadKeypair is returned when the key or cert file cannot be found or is not valid.
	ErrBadKeypair = "bad keypair conf"
)

// InitTLS performs a TLS handshake over the control channel.
// TODO(ainghazal): add checks for valid certificates etc on config time.
// TODO(ainghazal): this method can be splitted into a config part, that returns a tlsConf,
// and the tls-handshake part. This way we can invoke the tlsConf before dialing the connection,
// and raise any certificate errors early on.
func (c *control) InitTLS(conn net.Conn, session *session, opt *Options) (net.Conn, error) {

	// 1. configuration

	max := tls.VersionTLS13
	if opt.TLSMaxVer == "1.2" {
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
	if opt.Cert != "" {
		ca := x509.NewCertPool()
		caData, err := ioutil.ReadFile(opt.Ca)
		if err != nil {
			return nil, fmt.Errorf("%s %w", ErrBadCA, err)
		}
		ca.AppendCertsFromPEM(caData)
		cert, err := tls.LoadX509KeyPair(opt.Cert, opt.Key)
		if err != nil {
			return nil, fmt.Errorf("%s %w", ErrBadKeypair, err)
		}
		tlsConf.RootCAs = ca
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	// 2. handshake

	tlsConn, err := NewTLSConn(conn, session)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}
	tlsClient := tls.Client(tlsConn, tlsConf)

	if err := tlsClient.Handshake(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}

	logger.Info(fmt.Sprintf("TLS handshake done"))
	return net.Conn(tlsClient), nil
}
