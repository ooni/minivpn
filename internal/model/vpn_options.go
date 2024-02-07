package model

//
// Parse VPN options.
//
// Mostly, this file conforms to the format in the reference implementation.
// However, there are some additions that are specific. To avoid feature creep
// and fat dependencies, the internal implementation only supports mainline
// capabilities. It is still useful to carry all options in a single type,
// so it's up to the user of this library to do something useful with
// such options. The `extra` package provides some of these extra features, like
// obfuscation support.
//
// Following the configuration format in the reference implementation, `minivpn`
// allows including files in the main configuration file, but only for the `ca`,
// `cert` and `key` options.
//
// Each inline file is started by the line <option> and ended by the line
// </option>.
//
// Here is an example of an inline file usage:
//
// ```
// <cert>
// -----BEGIN CERTIFICATE-----
// [...]
// -----END CERTIFICATE-----
// </cert>
// ```

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type (
	// Compression describes a Compression type (e.g., stub).
	Compression string
)

const (
	// CompressionStub adds the (empty) compression stub to the packets.
	CompressionStub = Compression("stub")

	// CompressionEmpty is the empty compression.
	CompressionEmpty = Compression("empty")

	// CompressionLZONo is lzo-no (another type of no-compression, older).
	CompressionLZONo = Compression("lzo-no")
)

// Proto is the main vpn mode (e.g., TCP or UDP).
type Proto string

var _ fmt.Stringer = Proto("")

// String implements fmt.Stringer
func (p Proto) String() string {
	return string(p)
}

// ProtoTCP is used for vpn in TCP mode.
const ProtoTCP = Proto("tcp")

// ProtoUDP is used for vpn in UDP mode.
const ProtoUDP = Proto("udp")

// ErrBadConfig is the generic error returned for invalid config files
var ErrBadConfig = errors.New("openvpn: bad config")

// SupportCiphers defines the supported ciphers.
var SupportedCiphers = []string{
	"AES-128-CBC",
	"AES-192-CBC",
	"AES-256-CBC",
	"AES-128-GCM",
	"AES-192-GCM",
	"AES-256-GCM",
}

// SupportedAuth defines the supported authentication methods.
var SupportedAuth = []string{
	"SHA1",
	"SHA256",
	"SHA512",
}

// OpenVPNOptions make all the relevant openvpn configuration options accessible to the
// different modules that need it.
type OpenVPNOptions struct {
	// These options have the same name of OpenVPN options referenced in the official documentation:
	Remote    string
	Port      string
	Proto     Proto
	Username  string
	Password  string
	CAPath    string
	CertPath  string
	KeyPath   string
	CA        []byte
	Cert      []byte
	Key       []byte
	Cipher    string
	Auth      string
	TLSMaxVer string

	// Below are options that do not conform strictly to the OpenVPN configuration format, but still can
	// be understood by us in a configuration file:

	Compress   Compression
	ProxyOBFS4 string
}

// ReadConfigFile expects a string with a path to a valid config file,
// and returns a pointer to a Options struct after parsing the file, and an
// error if the operation could not be completed.
func ReadConfigFile(filePath string) (*OpenVPNOptions, error) {
	lines, err := getLinesFromFile(filePath)
	dir, _ := filepath.Split(filePath)
	if err != nil {
		return nil, err
	}
	return getOptionsFromLines(lines, dir)
}

// ShouldLoadCertsFromPath returns true when the options object is configured to load
// certificates from paths; false when we have inline certificates.
func (o *OpenVPNOptions) ShouldLoadCertsFromPath() bool {
	return o.CertPath != "" && o.KeyPath != "" && o.CAPath != ""
}

// HasAuthInfo returns true if:
// - we have paths for cert, key and ca; or
// - we have inline byte arrays for cert, key and ca; or
// - we have username + password info.
func (o *OpenVPNOptions) HasAuthInfo() bool {
	if o.CertPath != "" && o.KeyPath != "" && o.CAPath != "" {
		return true
	}
	if len(o.Cert) != 0 && len(o.Key) != 0 && len(o.CA) != 0 {
		return true
	}
	if o.Username != "" && o.Password != "" {
		return true
	}
	return false
}

// clientOptions is the options line we're passing to the OpenVPN server during the handshake.
const clientOptions = "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %sv4,cipher %s,auth %s,keysize %s,key-method 2,tls-client"

// ServerOptionsString produces a comma-separated representation of the options, in the same
// order and format that the OpenVPN server expects from us.
func (o *OpenVPNOptions) ServerOptionsString() string {
	if o.Cipher == "" {
		return ""
	}
	// TODO(ainghazal): this line of code crashes if the ciphers are not well formed
	keysize := strings.Split(o.Cipher, "-")[1]
	proto := strings.ToUpper(ProtoUDP.String())
	if o.Proto == ProtoTCP {
		proto = strings.ToUpper(ProtoTCP.String())
	}
	s := fmt.Sprintf(clientOptions, proto, o.Cipher, o.Auth, keysize)
	if o.Compress == CompressionStub {
		s = s + ",compress stub"
	} else if o.Compress == "lzo-no" {
		s = s + ",lzo-comp no"
	} else if o.Compress == CompressionEmpty {
		s = s + ",compress"
	}
	return s
}

// TunnelInfo holds state about the VPN TunnelInfo that has longer duration than a
// given session. This information is gathered at different stages:
// - during the handshake (mtu).
// - after server pushes config options(ip, gw).
type TunnelInfo struct {
	// GW is the Route Gateway.
	GW string

	// IP is the assigned IP.
	IP string

	// MTU is the configured MTU pushed by the remote.
	MTU int

	// NetMask is the netmask configured on the TUN interface, pushed by the ifconfig command.
	NetMask string

	// PeerID is the peer-id assigned to us by the remote.
	PeerID int
}

// NewTunnelInfoFromPushedOptions takes a map of string to array of strings, and returns
// a new tunnel struct with the relevant info.
func NewTunnelInfoFromPushedOptions(opts map[string][]string) *TunnelInfo {
	t := &TunnelInfo{}
	if r := opts["route"]; len(r) >= 1 {
		t.GW = r[0]
	} else if r := opts["route-gateway"]; len(r) >= 1 {
		t.GW = r[0]
	}
	ifconfig := opts["ifconfig"]
	if len(ifconfig) >= 1 {
		t.IP = ifconfig[0]
	}
	if len(ifconfig) >= 2 {
		t.NetMask = ifconfig[1]
	}
	peerID := opts["peer-id"]
	if len(peerID) == 1 {
		peer, err := strconv.Atoi(peerID[0])
		if err != nil {
			log.Println("Cannot parse peer-id:", err.Error())
		} else {
			t.PeerID = peer
		}
	}
	return t
}

// parseIntFromOption parses an int from a null-terminated string
func parseIntFromOption(s string) (int, error) {
	str := ""
	for i := 0; i < len(s); i++ {
		if byte(s[i]) == 0x00 {
			return strconv.Atoi(str)
		}
		str = str + string(s[i])
	}
	return 0, nil
}

// PushedOptionsAsMap returns a map for the server-pushed options,
// where the options are the keys and each space-separated value is the value.
// This function always returns an initialized map, even if empty.
func PushedOptionsAsMap(pushedOptions []byte) map[string][]string {
	optMap := make(map[string][]string)
	if len(pushedOptions) == 0 {
		return optMap
	}

	optStr := string(pushedOptions[:len(pushedOptions)-1])

	opts := strings.Split(optStr, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		k, v := vals[0], vals[1:]
		optMap[k] = v
	}
	return optMap
}

func parseProto(p []string, o *OpenVPNOptions) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", ErrBadConfig, "proto needs one arg")
	}
	m := p[0]
	switch m {
	case ProtoUDP.String():
		o.Proto = ProtoUDP
	case ProtoTCP.String():
		o.Proto = ProtoTCP
	default:
		return fmt.Errorf("%w: bad proto: %s", ErrBadConfig, m)

	}
	return nil
}

// TODO(ainghazal): all these little functions can be better tested if we return the options object too

func parseRemote(p []string, o *OpenVPNOptions) error {
	if len(p) != 2 {
		return fmt.Errorf("%w: %s", ErrBadConfig, "remote needs two args")
	}
	o.Remote, o.Port = p[0], p[1]
	return nil
}

func parseCipher(p []string, o *OpenVPNOptions) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", ErrBadConfig, "cipher expects one arg")
	}
	cipher := p[0]
	if !hasElement(cipher, SupportedCiphers) {
		return fmt.Errorf("%w: unsupported cipher: %s", ErrBadConfig, cipher)
	}
	o.Cipher = cipher
	return nil
}

func parseAuth(p []string, o *OpenVPNOptions) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", ErrBadConfig, "invalid auth entry")
	}
	auth := p[0]
	if !hasElement(auth, SupportedAuth) {
		return fmt.Errorf("%w: unsupported auth: %s", ErrBadConfig, auth)
	}
	o.Auth = auth
	return nil
}

func parseCA(p []string, o *OpenVPNOptions, basedir string) error {
	e := fmt.Errorf("%w: %s", ErrBadConfig, "ca expects a valid file")
	if len(p) != 1 {
		return e
	}
	ca := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, ca); !sub {
		return fmt.Errorf("%w: %s", ErrBadConfig, "ca must be below config path")
	}
	if !existsFile(ca) {
		return e
	}
	o.CAPath = ca
	return nil
}

func parseCert(p []string, o *OpenVPNOptions, basedir string) error {
	e := fmt.Errorf("%w: %s", ErrBadConfig, "cert expects a valid file")
	if len(p) != 1 {
		return e
	}
	cert := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, cert); !sub {
		return fmt.Errorf("%w: %s", ErrBadConfig, "cert must be below config path")
	}
	if !existsFile(cert) {
		return e
	}
	o.CertPath = cert
	return nil
}

func parseKey(p []string, o *OpenVPNOptions, basedir string) error {
	e := fmt.Errorf("%w: %s", ErrBadConfig, "key expects a valid file")
	if len(p) != 1 {
		return e
	}
	key := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, key); !sub {
		return fmt.Errorf("%w: %s", ErrBadConfig, "key must be below config path")
	}
	if !existsFile(key) {
		return e
	}
	o.KeyPath = key
	return nil
}

// parseAuthUser reads credentials from a given file, according to the openvpn
// format (user and pass on a line each). To avoid path traversal / LFI, the
// credentials file is expected to be in a subdirectory of the base dir.
func parseAuthUser(p []string, o *OpenVPNOptions, basedir string) error {
	e := fmt.Errorf("%w: %s", ErrBadConfig, "auth-user-pass expects a valid file")
	if len(p) != 1 {
		return e
	}
	auth := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, auth); !sub {
		return fmt.Errorf("%w: %s", ErrBadConfig, "auth must be below config path")
	}
	if !existsFile(auth) {
		return e
	}
	creds, err := getCredentialsFromFile(auth)
	if err != nil {
		return err
	}
	o.Username, o.Password = creds[0], creds[1]
	return nil
}

func parseCompress(p []string, o *OpenVPNOptions) error {
	if len(p) > 1 {
		return fmt.Errorf("%w: %s", ErrBadConfig, "compress: only empty/stub options supported")
	}
	if len(p) == 0 {
		o.Compress = CompressionEmpty
		return nil
	}
	if p[0] == "stub" {
		o.Compress = CompressionStub
		return nil
	}
	return fmt.Errorf("%w: %s", ErrBadConfig, "compress: only empty/stub options supported")
}

func parseCompLZO(p []string, o *OpenVPNOptions) error {
	if p[0] != "no" {
		return fmt.Errorf("%w: %s", ErrBadConfig, "comp-lzo: compression not supported")
	}
	o.Compress = "lzo-no"
	return nil
}

// parseTLSVerMax sets the maximum TLS version. This is currently ignored
// because we're using uTLS to parrot the Client Hello.
func parseTLSVerMax(p []string, o *OpenVPNOptions) error {
	if len(p) == 0 {
		o.TLSMaxVer = "1.3"
		return nil
	}
	if p[0] == "1.2" {
		o.TLSMaxVer = "1.2"
	}
	return nil
}

func parseProxyOBFS4(p []string, o *OpenVPNOptions) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", ErrBadConfig, "proto-obfs4: need a properly configured proxy")
	}
	// TODO(ainghazal): can validate the obfs4://... scheme here
	o.ProxyOBFS4 = p[0]
	return nil
}

var pMap = map[string]interface{}{
	"proto":           parseProto,
	"remote":          parseRemote,
	"cipher":          parseCipher,
	"auth":            parseAuth,
	"compress":        parseCompress,
	"comp-lzo":        parseCompLZO,
	"proxy-obfs4":     parseProxyOBFS4,
	"tls-version-max": parseTLSVerMax, // this is currently ignored because of uTLS
}

var pMapDir = map[string]interface{}{
	"ca":             parseCA,
	"cert":           parseCert,
	"key":            parseKey,
	"auth-user-pass": parseAuthUser,
}

func parseOption(o *OpenVPNOptions, dir, key string, p []string, lineno int) error {
	switch key {
	case "proto", "remote", "cipher", "auth", "compress", "comp-lzo", "tls-version-max", "proxy-obfs4":
		fn := pMap[key].(func([]string, *OpenVPNOptions) error)
		if e := fn(p, o); e != nil {
			return e
		}
	case "ca", "cert", "key", "auth-user-pass":
		fn := pMapDir[key].(func([]string, *OpenVPNOptions, string) error)
		if e := fn(p, o, dir); e != nil {
			return e
		}
	default:
		log.Printf("warn: unsupported key in line %d\n", lineno)
	}
	return nil
}

// getOptionsFromLines tries to parse all the lines coming from a config file
// and raises validation errors if the values do not conform to the expected
// format. The config file supports inline file inclusion for <ca>, <cert> and <key>.
func getOptionsFromLines(lines []string, dir string) (*OpenVPNOptions, error) {
	opt := &OpenVPNOptions{}

	// tag and inlineBuf are used to parse inline files.
	// these follow the format used by the reference openvpn implementation.
	// each block (any of ca, key, cert) is marked by a <option> line, and
	// closed by a </option> line; lines in between are expected to contain
	// the crypto block.
	tag := ""
	inlineBuf := new(bytes.Buffer)

	for lineno, l := range lines {
		if strings.HasPrefix(l, "#") {
			continue
		}
		l = strings.TrimSpace(l)

		// inline certs
		if isClosingTag(l) {
			// we expect an already existing inlineBuf
			e := parseInlineTag(opt, tag, inlineBuf)
			if e != nil {
				return nil, e
			}
			tag = ""
			inlineBuf = new(bytes.Buffer)
			continue
		}
		if tag != "" {
			inlineBuf.Write([]byte(l))
			inlineBuf.Write([]byte("\n"))
			continue
		}
		if isOpeningTag(l) {
			if len(inlineBuf.Bytes()) != 0 {
				// something wrong: an opening tag should not be found
				// when we still have bytes in the inline buffer.
				return opt, fmt.Errorf("%w: %s", ErrBadConfig, "tag not closed")
			}
			tag = parseTag(l)
			continue
		}

		// parse parts in the same line
		p := strings.Split(l, " ")
		if len(p) == 0 {
			continue
		}
		var (
			key   string
			parts []string
		)
		if len(p) == 1 {
			key = p[0]
		} else {
			key, parts = p[0], p[1:]
		}
		e := parseOption(opt, dir, key, parts, lineno)
		if e != nil {
			return nil, e
		}
	}
	return opt, nil
}

func isOpeningTag(key string) bool {
	switch key {
	case "<ca>", "<cert>", "<key>":
		return true
	default:
		return false
	}
}

func isClosingTag(key string) bool {
	switch key {
	case "</ca>", "</cert>", "</key>":
		return true
	default:
		return false
	}
}

func parseTag(tag string) string {
	switch tag {
	case "<ca>", "</ca>":
		return "ca"
	case "<cert>", "</cert>":
		return "cert"
	case "<key>", "</key>":
		return "key"
	default:
		return ""
	}
}

// parseInlineTag
func parseInlineTag(o *OpenVPNOptions, tag string, buf *bytes.Buffer) error {
	b := buf.Bytes()
	if len(b) == 0 {
		return fmt.Errorf("%w: empty inline tag: %d", ErrBadConfig, len(b))
	}
	switch tag {
	case "ca":
		o.CA = b
	case "cert":
		o.Cert = b
	case "key":
		o.Key = b
	default:
		return fmt.Errorf("%w: unknown tag: %s", ErrBadConfig, tag)
	}
	return nil
}

// hasElement checks if a given string is present in a string array. returns
// true if that is the case, false otherwise.
func hasElement(el string, arr []string) bool {
	for _, v := range arr {
		if v == el {
			return true
		}
	}
	return false
}

// existsFile returns true if the file to which the path refers to exists and
// is a regular file.
func existsFile(path string) bool {
	statbuf, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist) && statbuf.Mode().IsRegular()
}

// getLinesFromFile accepts a path parameter, and return a string array with
// its content and an error if the operation cannot be completed.
func getLinesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return nil, err
	}

	lines := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}
	return lines, nil
}

// getCredentialsFromFile accepts a path string parameter, and return a string
// array containing the credentials in that file, and an error if the operation
// could not be completed.
func getCredentialsFromFile(path string) ([]string, error) {
	lines, err := getLinesFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, err)
	}
	if len(lines) != 2 {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, "malformed credentials file")
	}
	if len(lines[0]) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, "empty username in creds file")
	}
	if len(lines[1]) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, "empty password in creds file")
	}
	return lines, nil
}

// toAbs return an absolute path if the given path is not already absolute; to
// do so, it will append the path to the given basedir.
func toAbs(path, basedir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(basedir, path)
}

// isSubdir checks if a given path is a subdirectory of another. It returns
// true if that's the case, and any error raise during the check.
func isSubdir(parent, sub string) (bool, error) {
	p, err := filepath.Abs(parent)
	if err != nil {
		return false, err
	}
	s, err := filepath.Abs(sub)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(s, p), nil
}
