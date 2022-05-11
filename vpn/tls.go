package vpn

//
// TLS initialization and read/write wrappers.
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

// initTLS returns a tls.Config matching the VPN options.
func initTLS(session *session, opt *Options) (*tls.Config, error) {

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
	return tlsConf, nil
}

// tlsHandshake performs the TLS handshake over the control channel, and return
// the TLS Client as a net.Conn; returns also any error during the handshake.
func tlsHandshake(tlsConn *TLSConn, tlsConf *tls.Config) (net.Conn, error) {

	tlsClient := tls.Client(tlsConn, tlsConf)

	if err := tlsClient.Handshake(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}

	logger.Info(fmt.Sprintf("TLS handshake done"))
	return net.Conn(tlsClient), nil
}
