package vpn

//
// TLS initialization and read/write wrappers.
//
// TODO(ainghazal): for the time being, we're using uTLS to parrot a ClientHello that can reasonably blend
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
	"strings"

	tls "github.com/refraction-networking/utls"
)

var (
	// ErrBadTLSHandshake is returned when the OpenVPN handshake failed.
	ErrBadTLSHandshake = errors.New("handshake failure")
	// ErrBadCA is returned when the CA file cannot be found or is not valid.
	ErrBadCA = errors.New("bad ca conf")
	ErrBadTA = errors.New("bad tls-auth conf")
	// ErrBadKeypair is returned when the key or cert file cannot be found or is not valid.
	ErrBadKeypair = errors.New("bad keypair conf")
	// ErrBadParrot is returned for errors during TLS parroting
	ErrBadParrot = errors.New("cannot parrot")
	// ErrCannotVerifyCertChain is returned for certificate chain validation errors.
	ErrCannotVerifyCertChain = errors.New("cannot verify chain")
)

// certVerifyOptionsNoCommonNameCheck returns a x509.VerifyOptions initialized with
// an empty string for the DNSName. This allows to skip CN verification.
func certVerifyOptionsNoCommonNameCheck() x509.VerifyOptions {
	return x509.VerifyOptions{DNSName: ""}
}

// certVerifyOptions is the options factory that the customVerify function will
// use; by default it configures VerifyOptions to skip the DNSName check.
var certVerifyOptions = certVerifyOptionsNoCommonNameCheck

// certPaths holds the paths for the cert, key, and ca used for OpenVPN
// certificate authentication.
type certPaths struct {
	certPath string
	keyPath  string
	caPath   string
	taPath   string
}

// loadCertAndCAFromPath parses the PEM certificates contained in the paths pointed by
// the passed certPaths and return a certConfig with the client and CA certificates.
func loadCertAndCAFromPath(pth certPaths) (*certConfig, error) {
	ca := x509.NewCertPool()
	caData, err := ioutil.ReadFile(pth.caPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadCA, err)
	}
	ok := ca.AppendCertsFromPEM(caData)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadCA, "cannot parse ca cert")
	}

	cfg := &certConfig{ca: ca}
	cfg.ta, err = loadTAFromFile(pth.taPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTA, err)
	}
	if pth.certPath != "" && pth.keyPath != "" {
		cert, err := tls.LoadX509KeyPair(pth.certPath, pth.keyPath)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadKeypair, err)
		}
		cfg.cert = cert
	}
	return cfg, nil
}

// certBytes holds the byte arrays for the cert, key, and ca used for OpenVPN
// certificate authentication.
type certBytes struct {
	cert []byte
	key  []byte
	ca   []byte
	ta   []byte
}

// loadCertAndCAFromBytes parses the PEM certificates from the byte arrays in the
// the passed certBytes, and return a certConfig with the client and CA certificates.
func loadCertAndCAFromBytes(crt certBytes) (*certConfig, error) {
	ca := x509.NewCertPool()
	ok := ca.AppendCertsFromPEM(crt.ca)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadCA, "cannot parse ca cert")
	}
	cfg := &certConfig{ca: ca}
	var err error
	cfg.ta, err = parseTAFromBytes(crt.ta)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTA, err)
	}
	if crt.cert != nil && crt.key != nil {
		cert, err := tls.X509KeyPair(crt.cert, crt.key)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadKeypair, err)
		}
		cfg.cert = cert
	}
	return cfg, nil
}

// authorityPinner is any object from which we can obtain a certpool containing
// a pinned Certificate Authority for verification.
type authorityPinner interface {
	authority() *x509.CertPool
}

// certConfig holds the parsed certificate and CA used for OpenVPN mutual
// certificate authentication.
type certConfig struct {
	cert tls.Certificate
	ca   *x509.CertPool
	ta   []byte
}

// newCertConfigFromOptions is a constructor that returns a certConfig object initialized
// from the paths specified in the passed Options object, and an error if it
// could not be properly built.
func newCertConfigFromOptions(o *Options) (*certConfig, error) {
	var cfg *certConfig
	var err error
	if o.certsFromPath() {
		cfg, err = loadCertAndCAFromPath(certPaths{
			certPath: o.CertPath,
			keyPath:  o.KeyPath,
			caPath:   o.CaPath,
			taPath:   o.TaPath,
		})
	} else {
		cfg, err = loadCertAndCAFromBytes(certBytes{
			cert: o.Cert,
			key:  o.Key,
			ca:   o.Ca,
			ta:   o.Ta,
		})
	}
	return cfg, err
}

func parseTAFromBytes(taBytes []byte) ([]byte, error) {
	return parseTAFromLines(
		strings.Split(string(taBytes), "\n"),
	)
}

func loadTAFromFile(taPath string) ([]byte, error) {
	lines, err := getLinesFromFile(taPath)
	if err != nil {
		return nil, err
	}
	return parseTAFromLines(lines)
}

func parseTAFromLines(lines []string) ([]byte, error) {
	const (
		initState = iota
		beginState
		endState
	)
	state := initState
	e := fmt.Errorf("invalid tls-auth key")
	var res []byte
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "BEGIN") {
			if state != initState {
				return nil, e
			}
			state = beginState
			continue
		}
		if strings.Contains(line, "END") {
			if state != beginState {
				return nil, e
			}
			state = endState
		}
		switch state {
		case initState:
			continue
		case beginState:
			res = append(res, []byte(line)...)
		case endState:
			break
		}
	}
	return res, nil
}

// authority implements authorityPinner interface.
func (c *certConfig) authority() *x509.CertPool {
	return c.ca
}

// ensure certConfig implements authorityPinner.
var _ authorityPinner = &certConfig{}

// verifyFun is the type expected by the VerifyPeerCertificate callback in tls.Config.
type verifyFun func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// customVerifyFactory returns a verifyFun callback that will verify any received certificates
// against the ca provided by the pased implementation of authorityPinner
func customVerifyFactory(pinner authorityPinner) verifyFun {
	// customVerify is a version of the verification routines that does not try to verify
	// the Common Name, since we don't know it a priori for a VPN gateway. Returns
	// an error if the verification fails.
	// From tls/common documentation: If normal verification is disabled by
	// setting InsecureSkipVerify, [...] then this callback will be considered but
	// the verifiedChains argument will always be nil.
	customVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// we assume (from docs) that we're always given the
		// leaf certificate as the first cert in the array.
		leaf, _ := x509.ParseCertificate(rawCerts[0])
		if leaf == nil {
			return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, "nothing to verify")
		}
		// By default has DNSName verification disabled.
		opts := certVerifyOptions()
		// Set the configured CA(s) as the certificate pool to verify against.
		opts.Roots = pinner.authority()

		if _, err := leaf.Verify(opts); err != nil {
			return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, err)
		}
		return nil
	}
	return customVerify
}

// initTLS returns a tls.Config matching the VPN options. Internally, it uses
// the verify function returned by the global customVerifyFactory,
// verification function since verifying the ServerName does not make sense in
// the context of establishing a VPN session: we perform mutual TLS
// Authentication with the custom CA.
func initTLS(session *session, cfg *certConfig) (*tls.Config, error) {
	if session == nil || cfg == nil {
		return nil, fmt.Errorf("%w: %s", errBadInput, "nil args")
	}

	customVerify := customVerifyFactory(cfg)

	tlsConf := &tls.Config{
		// the certificate we've loaded from the config file
		Certificates: []tls.Certificate{cfg.cert},
		// crypto/tls wants either ServerName or InsecureSkipVerify set ...
		InsecureSkipVerify: true,
		// ...but we pass our own verification function that verifies against the CA and ignores the ServerName
		VerifyPeerCertificate: customVerify,
		// disable DynamicRecordSizing to lower distinguishability.
		DynamicRecordSizingDisabled: true,
		// uTLS does not pick min/max version from the passed spec
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	} //#nosec G402

	return tlsConf, nil
}

// tlsHandshake performs the TLS handshake over the control channel, and return
// the TLS Client as a net.Conn; returns also any error during the handshake.
func tlsHandshake(tlsConn *controlChannelTLSConn, tlsConf *tls.Config) (net.Conn, error) {
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

// vpnClientHelloHex is the hexadecimal representation of a capture from the reference openvpn implementation.
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

// global variables to allow monkeypatching in tests.
var (
	initTLSFn      = initTLS
	tlsFactoryFn   = parrotTLSFactory
	tlsHandshakeFn = tlsHandshake
)
