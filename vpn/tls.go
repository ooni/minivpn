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
	// ErrCannotVerifyCertChain is returned for certificate chain validation errors.
	ErrCannotVerifyCertChain = errors.New("cannot verify chain")
)

// certVerifyOptionsNoCommonNameCheck is a x509.VerifyOptions initialized with
// an empty string for the DNSName. This allows to skip CN verification.
var certVerifyOptionsNoCommonNameCheck = x509.VerifyOptions{DNSName: ""}

// certVerifyOptions is the option that the customVerify function will use.
var certVerifyOptions = certVerifyOptionsNoCommonNameCheck

// customVerify is a version of the verification routines that does not try to verify
// the Common Name, since we don't know it a priori for a VPN gateway. Returns
// an error if the verification fails.
// From tls/common documentation: If normal verification is disabled by
// setting InsecureSkipVerify, [...] then this callback will be considered but
// the verifiedChains argument will always be nil.
func customVerify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	roots := x509.NewCertPool()
	var leaf *x509.Certificate

	for i, rawCert := range rawCerts {
		cert, _ := x509.ParseCertificate(rawCert)
		if cert != nil {
			if i == 0 {
				leaf = cert
			} else {
				roots.AddCert(cert)
			}
		}
	}

	opts := certVerifyOptions
	opts.Roots = roots

	var err error
	if leaf == nil {
		return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, "nothing to verify")

	}
	_, err = leaf.Verify(opts)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, err)
	}
	return nil
}

// initTLS returns a tls.Config matching the VPN options. We pass a custom
// verification function since verifying the ServerName does not make sense in
// the context of establishing a VPN session: we perform mutual TLS
// Authentication with the custom CA.
func initTLS(session *session, opt *Options) (*tls.Config, error) {
	if session == nil || opt == nil {
		return nil, fmt.Errorf("%w:%s", errBadInput, "nil args")
	}

	// We are not passing min/max tls versions because the ClientHello spec
	// that we use as reference already sets "reasonable" values.

	tlsConf := &tls.Config{
		// crypto/tls wants either ServerName or InsecureSkipVerify set ...
		InsecureSkipVerify: true,
		// ...but we pass our own verification function that ignores the ServerName
		VerifyPeerCertificate:       customVerify,
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
// openvpn=2.5.5,openssl=3.0.2
// You can use https://github.com/ainghazal/sniff/tree/main/clienthello to
// analyze a ClientHello from the wire or pcap.
var vpnClientHelloHex = `1603010114010001100303534e0a0f2687b240f7c7dfbb51c4aac33639f28173aa5d7bcebb159695ab0855208b835bf240a83df66885d6747b5bbf1b631e8c34ae469c629d7eb76e247128eb0032130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c013003300ff01000095000b000403000102000a00160014001d0017001e00190018010001010102010301040016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020a10bc24becb583293c317220e6725205d3a177a4a974090f6ffcf13a43da7035`

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
