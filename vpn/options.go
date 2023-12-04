package vpn

//
// Parse VPN options.
//
// Mostly, this file conforms to the format in the reference implementation.
// However, there are some additions that are specific. To avoid feature creep
// and fat dependencies, the main `vpn` module only supports mainline
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
	// compression describes a compression type (e.g., stub).
	compression string
)

const (
	// compressionStub adds the (empty) compression stub to the packets.
	compressionStub = compression("stub")

	// compressionEmpty is the empty compression.
	compressionEmpty = compression("empty")

	// compressionLZONo is lzo-no (another type of no-compression, older).
	compressionLZONo = compression("lzo-no")
)

type (
	// proto is the main vpn mode (e.g., TCP or UDP).
	proto string
)

func (p proto) String() string {
	return string(p)
}

const (
	// protoTCP is used for vpn in TCP mode.
	protoTCP = proto("tcp")

	// protoUDP is used for vpn in UDP mode.
	protoUDP = proto("udp")
)

var (
	// errBadCfg is the generic error returned for invalid config files
	errBadCfg = errors.New("bad config")
)

var supportedCiphers = []string{
	"AES-128-CBC",
	"AES-192-CBC",
	"AES-256-CBC",
	"AES-128-GCM",
	"AES-192-GCM",
	"AES-256-GCM",
}

var supportedAuth = []string{
	"SHA1",
	"SHA256",
	"SHA512",
}

// Options make all the relevant configuration options accessible to the
// different modules that need it.
type Options struct {
	Remote string
	Port   string
	//TODO(https://github.com/ooni/minivpn/issues/25): Proto should be changed to a string and checked against known types.
	Proto     int
	Username  string
	Password  string
	CaPath    string
	CertPath  string
	KeyPath   string
	TaPath    string
	Ca        []byte
	Cert      []byte
	Key       []byte
	Ta        []byte
	Compress  compression
	Cipher    string
	Auth      string
	TLSMaxVer string
	// below are options that do not conform to the OpenVPN configuration format.
	ProxyOBFS4 string
	Log        Logger
}

// NewOptionsFromFilePath expects a string with a path to a valid config file,
// and returns a pointer to a Options struct after parsing the file, and an
// error if the operation could not be completed.
func NewOptionsFromFilePath(filePath string) (*Options, error) {
	lines, err := getLinesFromFile(filePath)
	dir, _ := filepath.Split(filePath)
	if err != nil {
		return nil, err
	}
	return getOptionsFromLines(lines, dir)
}

// certsFromPath returns true when the options object is configured to load
// certificates from paths; false when we have inline certificates.
func (o *Options) certsFromPath() bool {
	return o.CertPath != "" && o.KeyPath != "" && o.CaPath != "" && o.TaPath != ""
}

// hasAuthInfo returns true if:
// - we have paths for cert, key and ca; or
// - we have inline byte arrays for cert, key and ca; or
// - we have username + password info.
func (o *Options) hasAuthInfo() bool {
	if o.CertPath != "" && o.KeyPath != "" && o.CaPath != "" {
		return true
	}
	if len(o.Cert) != 0 && len(o.Key) != 0 && len(o.Ca) != 0 {
		return true
	}
	if o.Username != "" && o.Password != "" {
		return true
	}
	return false
}

const clientOptions = "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %sv4,cipher %s,auth %s,keysize %s,key-method 2,tls-client"

// String produces a comma-separated representation of the options, in the same
// order and format that the openvpn server expects from us.
func (o *Options) String() string {
	if o.Cipher == "" {
		return ""
	}
	keysize := strings.Split(o.Cipher, "-")[1]
	proto := strings.ToUpper(protoUDP.String())
	if o.Proto == TCPMode {
		proto = strings.ToUpper(protoTCP.String())
	}
	s := fmt.Sprintf(
		clientOptions,
		proto, o.Cipher, o.Auth, keysize)
	if o.Compress == compressionStub {
		s = s + ",compress stub"
	} else if o.Compress == "lzo-no" {
		s = s + ",lzo-comp no"
	} else if o.Compress == compressionEmpty {
		s = s + ",compress"
	}
	logger.Debugf("Local opts:  %s", s)
	return s
}

// newTunnelInfoFromRemoteOptionsString parses the options string returned by
// server. it returns a new tunnel object where the needed fields have been
// updated. At the moment, we only parse the tun-mtu parameter.
func newTunnelInfoFromRemoteOptionsString(remoteOpts string) *tunnelInfo {
	t := &tunnelInfo{}
	opts := strings.Split(remoteOpts, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		if len(vals) < 2 {
			continue
		}
		k, v := vals[0], vals[1:]
		if k == "tun-mtu" {
			mtu, err := strconv.Atoi(v[0])
			if err != nil {
				log.Println("bad mtu:", err)
				continue
			}
			t.mtu = mtu
		}
	}
	return t
}

// newTunnelInfoFromPushedOptions takes a map of string to array of strings, and returns
// a new tunnel struct with the relevant info.
func newTunnelInfoFromPushedOptions(opts map[string][]string) *tunnelInfo {
	t := &tunnelInfo{}
	if r := opts["route"]; len(r) >= 1 {
		t.gw = r[0]
	} else if r := opts["route-gateway"]; len(r) >= 1 {
		t.gw = r[0]
	}
	ip := opts["ifconfig"]
	if len(ip) >= 1 {
		t.ip = ip[0]
	}
	peerID := opts["peer-id"]
	if len(peerID) == 1 {
		i, err := parseIntFromOption(peerID[0])
		if err == nil {
			t.peerID = i
		} else {
			log.Println("Cannot parse peer-id:", err.Error())
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

// pushedOptionsAsMap returns a map for the server-pushed options,
// where the options are the keys and each space-separated value is the value.
// This function always returns an initialized map, even if empty.
func pushedOptionsAsMap(pushedOptions []byte) map[string][]string {
	optMap := make(map[string][]string)
	if pushedOptions == nil || len(pushedOptions) == 0 {
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

func parseProto(p []string, o *Options) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", errBadCfg, "proto needs one arg")
	}
	m := p[0]
	switch m {
	case protoUDP.String():
		o.Proto = UDPMode
	case protoTCP.String():
		o.Proto = TCPMode
	default:
		return fmt.Errorf("%w: bad proto: %s", errBadCfg, m)

	}
	return nil
}

// TODO(ainghazal): all these little functions can be better tested if we return the options object too

func parseRemote(p []string, o *Options) error {
	if len(p) != 2 {
		return fmt.Errorf("%w: %s", errBadCfg, "remote needs two args")
	}
	o.Remote, o.Port = p[0], p[1]
	return nil
}

func parseCipher(p []string, o *Options) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", errBadCfg, "cipher expects one arg")
	}
	cipher := p[0]
	if !hasElement(cipher, supportedCiphers) {
		return fmt.Errorf("%w: unsupported cipher: %s", errBadCfg, cipher)
	}
	o.Cipher = cipher
	return nil
}

func parseAuth(p []string, o *Options) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", errBadCfg, "invalid auth entry")
	}
	auth := p[0]
	if !hasElement(auth, supportedAuth) {
		return fmt.Errorf("%w: unsupported auth: %s", errBadCfg, auth)
	}
	o.Auth = auth
	return nil
}

func parseCA(p []string, o *Options, basedir string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "ca expects a valid file")
	if len(p) != 1 {
		return e
	}
	ca := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, ca); !sub {
		return fmt.Errorf("%w: %s", errBadCfg, "ca must be below config path")
	}
	if !existsFile(ca) {
		return e
	}
	o.CaPath = ca
	return nil
}

func parseTA(p []string, o *Options, basedir string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "ta expects a valid file")
	if len(p) != 1 {
		return e
	}
	ta := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, ta); !sub {
		return fmt.Errorf("%w: %s", errBadCfg, "ta must be below config path")
	}
	if !existsFile(ta) {
		return e
	}
	o.TaPath = ta
	return nil
}

func parseCert(p []string, o *Options, basedir string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "cert expects a valid file")
	if len(p) != 1 {
		return e
	}
	cert := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, cert); !sub {
		return fmt.Errorf("%w: %s", errBadCfg, "cert must be below config path")
	}
	if !existsFile(cert) {
		return e
	}
	o.CertPath = cert
	return nil
}

func parseKey(p []string, o *Options, basedir string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "key expects a valid file")
	if len(p) != 1 {
		return e
	}
	key := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, key); !sub {
		return fmt.Errorf("%w: %s", errBadCfg, "key must be below config path")
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
func parseAuthUser(p []string, o *Options, basedir string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "auth-user-pass expects a valid file")
	if len(p) != 1 {
		return e
	}
	auth := toAbs(p[0], basedir)
	if sub, _ := isSubdir(basedir, auth); !sub {
		return fmt.Errorf("%w: %s", errBadCfg, "auth must be below config path")
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

func parseCompress(p []string, o *Options) error {
	if len(p) > 1 {
		return fmt.Errorf("%w: %s", errBadCfg, "compress: only empty/stub options supported")
	}
	if len(p) == 0 {
		o.Compress = compressionEmpty
		return nil
	}
	if p[0] == "stub" {
		o.Compress = compressionStub
		return nil
	}
	return fmt.Errorf("%w: %s", errBadCfg, "compress: only empty/stub options supported")
}

func parseCompLZO(p []string, o *Options) error {
	if p[0] != "no" {
		return fmt.Errorf("%w: %s", errBadCfg, "comp-lzo: compression not supported")
	}
	o.Compress = "lzo-no"
	return nil
}

// parseTLSVerMax sets the maximum TLS version. This is currently ignored
// because we're using uTLS to parrot the Client Hello.
func parseTLSVerMax(p []string, o *Options) error {
	if o == nil {
		return errBadInput
	}
	if len(p) == 0 {
		o.TLSMaxVer = "1.3"
		return nil
	}
	if p[0] == "1.2" {
		o.TLSMaxVer = "1.2"
	}
	return nil
}

func parseProxyOBFS4(p []string, o *Options) error {
	if len(p) != 1 {
		return fmt.Errorf("%w: %s", errBadCfg, "proto-obfs4: need a properly configured proxy")
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
	"tls-auth":       parseTA,
}

func parseOption(o *Options, dir, key string, p []string, lineno int) error {
	switch key {
	case "proto", "remote", "cipher", "auth", "compress", "comp-lzo", "tls-version-max", "proxy-obfs4":
		fn := pMap[key].(func([]string, *Options) error)
		if e := fn(p, o); e != nil {
			return e
		}
	case "ca", "cert", "key", "auth-user-pass", "tls-auth":
		fn := pMapDir[key].(func([]string, *Options, string) error)
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
// format.
// the config file supports inline file inclusion for <ca>, <cert> and <key>.
func getOptionsFromLines(lines []string, dir string) (*Options, error) {
	opt := &Options{}

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
				return opt, fmt.Errorf("%w: %s", errBadInput, "tag not closed")
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
	case "<ca>", "<cert>", "<key>", "<tls-auth>":
		return true
	default:
		return false
	}
}

func isClosingTag(key string) bool {
	switch key {
	case "</ca>", "</cert>", "</key>", "</tls-auth>":
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
	case "<tls-auth>", "</tls-auth>":
		return "ta"
	default:
		return ""
	}
}

// parseInlineTag
func parseInlineTag(o *Options, tag string, buf *bytes.Buffer) error {
	b := buf.Bytes()
	if len(b) == 0 {
		return fmt.Errorf("%w: empty inline tag: %d", errBadInput, len(b))
	}
	switch tag {
	case "ca":
		o.Ca = b
	case "cert":
		o.Cert = b
	case "key":
		o.Key = b
	case "ta":
		o.Ta = b
	default:
		return fmt.Errorf("%w: unknown tag: %s", errBadInput, tag)
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
	f, err := os.Open(path) //#nosec G304
	defer func() {
		if err := f.Close(); err != nil {
			logger.Errorf("Error closing file: %s\n", err)
		}
	}()
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
		return nil, fmt.Errorf("%w: %s", errBadCfg, err)
	}
	if len(lines) != 2 {
		return nil, fmt.Errorf("%w: %s", errBadCfg, "malformed credentials file")
	}
	if len(lines[0]) == 0 {
		return nil, fmt.Errorf("%w: %s", errBadCfg, "empty username in creds file")
	}
	if len(lines[1]) == 0 {
		return nil, fmt.Errorf("%w: %s", errBadCfg, "empty password in creds file")
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
