package vpn

//
// TLS initialization and read/write wrappers.
//
// TODO for the time being, we're using uTLS to parrot a ClientHello that can reasonably blend
// with a recent openvpn+openssl client (2.5.x). We might want to revisit this
// in the near future and perhaps expose other TLS Factories.
//

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	tls "github.com/refraction-networking/utls"
)

var (
	// ErrBadTLSHandshake is returned when the OpenVPN handshake failed.
	ErrBadTLSHandshake = errors.New("handshake failure")
	// ErrBadCA is returned when the CA file cannot be found or is not valid.
	ErrBadCA = errors.New("bad ca conf")
	// ErrBadKeypair is returned when the key or cert file cannot be found or is not valid.
	ErrBadKeypair = errors.New("bad keypair conf")
	// ErrBadParrot is returned for errors during TLS parroting
	ErrBadParrot = errors.New("cannot parrot")
)

// initTLS returns a tls.Config matching the VPN options.
func initTLS(session *session, opt *Options) (*tls.Config, error) {
	if session == nil || opt == nil {
		return nil, fmt.Errorf("%w:%s", errBadInput, "nil args")
	}

	// We are not passing min/max tls versions because the ClientHello spec
	// that we use as reference already sets "reasonable" values.

	tlsConf := &tls.Config{
		// TODO(ainghazal): make sure I end up verifying the peer
		// certificate correctly. We cannot use name verification, since
		// the ServerName is not known a priory. Probably must pass a
		// VerifyConnection or VerifyPeercertificate callback?
		// ServerName:         "vpnserver",
		// VerifyPeerCertificate: ...,
		InsecureSkipVerify:          true,
		DynamicRecordSizingDisabled: true,
	} //#nosec G402

	// TODO(ainghazal): we assume a non-empty cert means we've got also a
	// valid ca and key, but we need a validation function that accepts an Options object.
	if opt.Cert != "" {
		ca := x509.NewCertPool()
		caData, err := ioutil.ReadFile(opt.Ca)
		if err != nil {
			return nil, fmt.Errorf("%w:%s", ErrBadCA, err)
		}
		ok := ca.AppendCertsFromPEM(caData)
		if !ok {
			return nil, fmt.Errorf("%w:%s", ErrBadCA, "cannot parse ca cert")
		}

		cert, err := tls.LoadX509KeyPair(opt.Cert, opt.Key)
		if err != nil {
			return nil, fmt.Errorf("%w:%s", ErrBadKeypair, err)
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
	tlsClient, err := tlsFactoryFn(tlsConn, tlsConf)
	if err != nil {
		return nil, err
	}
	if err := tlsClient.Handshake(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}
	return tlsClient, nil
}

// handshaker is a custom interface that we define here to be able to mock
// the tls.Conn implementation.
type handshaker interface {
	net.Conn
	Handshake() error
}

// defaultTLSFactory returns an implementer of the handshaker interface; that
// is, the default tls.Client factory; and an error.
// we're not using the default factory right now, but it comes handy to be able
// to compare the fingerprints with a golang TLS handshake.
func defaultTLSFactory(conn net.Conn, config *tls.Config) (handshaker, error) {
	c := tls.Client(conn, config)
	return c, nil
}

// vpnClientHelloHex is the hexadecimal respresentation of a capture from the reference openvpn implementation.
const vpnClientHelloHex = `16030100e8010000e40303fe0b6526568ada469f8a7996b79b2598208481dc43fe56081614c7e0e8b9bd8920ddb7565358d398109fb7934c077eb0234c98839b2578046904849b2b76156ab1000a130213031301c02c00ff01000091000b000403000102000a00160014001d0017001e00190018010001010102010301040016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020a9cf1d61f8caee159b9a4dc684d9319e2349f80f6e82ff7b755b820ff33fa75f`

// parrotTLSFactory returns an implementer of the handshaker interface; in this
// case, a parroting implementation; and an error.
func parrotTLSFactory(conn net.Conn, config *tls.Config) (handshaker, error) {
	fingerprinter := &tls.Fingerprinter{AllowBluntMimicry: true}
	rawOpenVPNClientHelloBytes, err := hex.DecodeString(vpnClientHelloHex)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot decode raw fingerprint: %s", ErrBadParrot, err)
	}
	generatedSpec, err := fingerprinter.FingerprintClientHello(rawOpenVPNClientHelloBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: fingerprinting failed: %s", ErrBadParrot, err)
	}
	client := tls.UClient(conn, config, tls.HelloCustom)
	if err := client.ApplyPreset(generatedSpec); err != nil {
		return nil, fmt.Errorf("%w: cannot apply spec: %s", ErrBadParrot, err)
	}
	return client, nil
}

var tlsFactoryFn = parrotTLSFactory
var tlsHandshakeFn = tlsHandshake
