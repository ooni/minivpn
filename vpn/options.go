package vpn

// Parse VPN options.

// Mostly, this file conforms to the format in the reference implementation.
// However, there are some additions that are specific. To avoid feature creep
// and fat dependencies, the main `vpn` module only supports mainline
// capabilities. It is still useful to carry all options in a single type,
// so it's up to the user of this library to do something useful with
// such options. The `extra` package provides some of these features, like
// obfuscation support.

import (
	"bufio"
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

/*
// TODO(ainghazal): this could inform the selection of ciphers in initTLS
// but some of these particular ciphermodes are problematic because stdlib in go
// does not implement finite DH. adding them is gonna be hacky

var supportedTLSCipher = []string{
	// DHE-RSA-AES128-SHA -> riseup legacy; unsupported!
	// TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
	// TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
}
*/

// Options make all the relevant configuration options accessible to the
// different modules that need it.
type Options struct {
	Remote    string
	Port      string
	Proto     int
	Username  string
	Password  string
	CaPath    string
	CertPath  string
	KeyPath   string
	Ca        []byte
	Cert      []byte
	Key       []byte
	Compress  compression
	Cipher    string
	Auth      string
	TLSMaxVer string
	// below are options that do not conform to the OpenVPN configuration format.
	ProxyOBFS4 string
	Log        Logger
}

const clientOptions = "V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %sv4,cipher %s,auth %s,keysize %s,key-method 2,tls-client"

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
	}
	logger.Debugf("Local opts:  %s", s)
	return s
}

// parseRemoteOptions parses the options returned or pushed by server. it
// returns the tunnel object where the needed fields have been updated.
func parseRemoteOptions(tunnel *tunnel, remoteOpts string) *tunnel {
	opts := strings.Split(remoteOpts, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		k, v := vals[0], vals[1:]
		if k == "tun-mtu" {
			mtu, err := strconv.Atoi(v[0])
			if err != nil {
				log.Println("bad mtu:", err)
				continue
			}
			tunnel.mtu = mtu
		}
	}
	return tunnel
}

// I don't think I want to do much with the pushed options for now, other
// than extracting the tunnel ip, but it can be useful to parse them into a map
// and compare if there's a strong disagreement with the remote opts
// XXX right now this only returns the ip. we could accept a tunnel struct and
// write to it.
func parsePushedOptions(pushedOptions []byte) string {
	if pushedOptions == nil || len(pushedOptions) == 0 {
		return ""
	}
	optStr := string(pushedOptions[:len(pushedOptions)-1])
	opts := strings.Split(optStr, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")

		k, v := vals[0], vals[1:]
		if k == "ifconfig" {
			return v[0]
		}
	}
	return ""
}

// ParseConfigFile expects a path to a valid config file and returns an Option
// object after parsing the file.
func ParseConfigFile(filePath string) (*Options, error) {
	lines, err := getLinesFromFile(filePath)
	dir, _ := filepath.Split(filePath)
	if err != nil {
		return nil, err
	}
	return getOptionsFromLines(lines, dir)
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

func parseAuthUser(p []string, o *Options) error {
	if len(p) != 1 || !existsFile(p[0]) {
		return fmt.Errorf("%w: %s", errBadCfg, "auth-user-pass expects a valid file")
	}
	creds, err := getCredentialsFromFile(p[0])
	if err != nil {
		return err
	}
	o.Username, o.Password = creds[0], creds[1]
	return nil
}

func parseCA(p []string, o *Options, d string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "ca expects a valid file")
	if len(p) != 1 {
		return e
	}
	ca := filepath.Join(d, p[0])
	if !existsFile(ca) {
		return e
	}
	o.CaPath = ca
	return nil
}

func parseCert(p []string, o *Options, d string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "cert expects a valid file")
	if len(p) != 1 {
		return e
	}
	cert := filepath.Join(d, p[0])
	if !existsFile(cert) {
		return e
	}
	o.CertPath = cert
	return nil
}

func parseKey(p []string, o *Options, d string) error {
	e := fmt.Errorf("%w: %s", errBadCfg, "key expects a valid file")
	if len(p) != 1 {
		return e
	}
	key := filepath.Join(d, p[0])
	if !existsFile(key) {
		return e
	}
	o.KeyPath = key
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
	"auth-user-pass":  parseAuthUser,
	"compress":        parseCompress,
	"comp-lzo":        parseCompLZO,
	"proxy-obfs4":     parseProxyOBFS4,
	"tls-version-max": parseTLSVerMax, // this is currently ignored because of uTLS
}

var pMapDir = map[string]interface{}{
	"ca":   parseCA,
	"cert": parseCert,
	"key":  parseKey,
}

func parseOption(o *Options, dir, key string, p []string) error {
	switch key {
	case "proto", "remote", "cipher", "auth", "auth-user-pass", "compress", "comp-lzo", "tls-version-max", "proxy-obfs4":
		fn := pMap[key].(func([]string, *Options) error)
		if e := fn(p, o); e != nil {
			return e
		}
	case "ca", "cert", "key":
		fn := pMapDir[key].(func([]string, *Options, string) error)
		if e := fn(p, o, dir); e != nil {
			return e
		}
	default:
		log.Println("warn: unsupported key:", key)
	}
	return nil
}

// getOptionsFromLines tries to parse all the lines coming from a config file
// and raises validation errors if the values do not conform to the expected
// format.
func getOptionsFromLines(lines []string, dir string) (*Options, error) {
	s := &Options{}

	for _, l := range lines {
		if strings.HasPrefix(l, "#") {
			continue
		}
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
		e := parseOption(s, dir, key, parts)
		if e != nil {
			return nil, e
		}
	}
	return s, nil
}

func hasElement(el string, arr []string) bool {
	for _, v := range arr {
		if v == el {
			return true
		}
	}
	return false
}

func existsFile(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

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
