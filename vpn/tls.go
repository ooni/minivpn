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
	if session == nil || opt == nil {
		return nil, fmt.Errorf("%w:%s", errBadInput, "nil args")
	}
	max := tls.VersionTLS13
	if opt.TLSMaxVer == "1.2" {
		max = tls.VersionTLS12
	}

	tlsConf := &tls.Config{
		// TODO(ainghazal): make sure I end up verifying the peer
		// certificate correctly. We cannot use name verification, since
		// the ServerName is not known a priory. Probably must pass a
		// VerifyConnection or VerifyPeercertificate callback?
		// ServerName:         "vpnserver",
		// VerifyPeerCertificate: ...,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         uint16(max),
	} //#nosec G402

	// TODO(ainghazal): we assume a non-empty cert means we've got also a
	// valid ca and key, but we need a validation function that accepts an Options object.
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

var initTLSFn = initTLS

// tlsHandshake performs the TLS handshake over the control channel, and return
// the TLS Client as a net.Conn; returns also any error during the handshake.
func tlsHandshake(tlsConn *TLSConn, tlsConf *tls.Config) (net.Conn, error) {
	tlsClient := tls.Client(tlsConn, tlsConf)
	if err := tlsClient.Handshake(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}
	return tlsClient, nil
}

var tlsHandshakeFn = tlsHandshake
