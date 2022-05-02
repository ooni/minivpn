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
	"strings"
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
// TODO this should inform the selection of ciphers in initTLS
var supportedTLSCipher = []string{
	// DHE-RSA-AES128-SHA -> riseup legacy; this is problematic because go
	// tls doesn't implement finite DH.
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
	Ca        string
	Cert      string
	Key       string
	Compress  string
	Cipher    string
	Auth      string
	TLSMaxVer string
	// below are options that do not conform to the OpenVPN configuration format.
	ProxyOBFS4 string
}

func getHashLength(s string) int {
	switch s {
	case "sha1":
		return 20
	case "sha256":
		return 32
	case "sha512":
		return 64
	}
	return 0
}

const clientOptions = "V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %sv4,cipher %s,auth %s,keysize %s,key-method 2,tls-client"

func optionsString(opts *Options) string {
	keysize := strings.Split(opts.Cipher, "-")[1]
	proto := "UDP"
	if opts.Proto == TCPMode {
		proto = "TCP"
	}
	s := fmt.Sprintf(
		clientOptions,
		proto, opts.Cipher, opts.Auth, keysize)
	if opts.Compress == "stub" {
		s = s + ",compress stub"
	} else if opts.Compress == "lzo-no" {
		s = s + ",lzo-comp no"
	}
	log.Println("Local opts: ", s)
	return s
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
		return fmt.Errorf("proto needs one arg")
	}
	m := p[0]
	switch m {
	case "udp":
		o.Proto = UDPMode
	case "tcp":
		o.Proto = TCPMode
	default:
		log.Println("err: unsupported proto:", m)
		return errors.New("bad mode: " + m)

	}
	return nil
}

func parseRemote(p []string, o *Options) error {
	if len(p) != 2 {
		return fmt.Errorf("remote needs two args")
	}
	o.Remote, o.Port = p[0], p[1]
	return nil
}

func parseCipher(p []string, o *Options) error {
	if len(p) != 1 {
		return fmt.Errorf("cipher expects one arg")
	}
	cipher := p[0]
	if !hasElement(cipher, supportedCiphers) {
		return fmt.Errorf("unsupported cipher: %s", cipher)
	}
	o.Cipher = cipher
	return nil
}

func parseAuth(p []string, o *Options) error {
	if len(p) != 1 {
		return fmt.Errorf("invalid auth entry")
	}
	auth := p[0]
	if !hasElement(auth, supportedAuth) {
		return fmt.Errorf("unsupported auth: %s", auth)
	}
	o.Auth = auth
	return nil
}

func parseAuthUser(p []string, o *Options) error {
	if len(p) != 1 || !existsFile(p[0]) {
		return fmt.Errorf("auth-user-pass expects a valid file")
	}
	creds, err := getCredentialsFromFile(p[0])
	if err != nil {
		return err
	}
	o.Username, o.Password = creds[0], creds[1]
	return nil
}

func parseCA(p []string, o *Options, d string) error {
	e := fmt.Errorf("ca expects a valid file")
	if len(p) != 1 {
		return e
	}
	ca := filepath.Join(d, p[0])
	if !existsFile(ca) {
		return e
	}
	o.Ca = ca
	return nil
}

func parseCert(p []string, o *Options, d string) error {
	e := fmt.Errorf("cert expects a valid file")
	if len(p) != 1 {
		return e
	}
	cert := filepath.Join(d, p[0])
	if !existsFile(cert) {
		return e
	}
	o.Cert = cert
	return nil
}

func parseKey(p []string, o *Options, d string) error {
	e := fmt.Errorf("key expects a valid file")
	if len(p) != 1 {
		return e
	}
	key := filepath.Join(d, p[0])
	if !existsFile(key) {
		return e
	}
	o.Key = key
	return nil
}

func parseCompress(p []string, o *Options) error {
	if len(p) > 1 {
		return fmt.Errorf("compress: only empty/stub options supported")
	}
	if len(p) == 0 {
		o.Compress = "empty"
		return nil
	}
	if p[0] == "stub" {
		o.Compress = "stub"
		return nil
	}
	return fmt.Errorf("compress: only empty/stub options supported")
}

func parseCompLZO(p []string, o *Options) error {
	if p[0] != "no" {
		return fmt.Errorf("comp-lzo: compression not supported, sorry")
	}
	o.Compress = "lzo-no"
	return nil
}

func parseTLSVerMax(p []string, o *Options) error {
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
		return fmt.Errorf("proto-obfs4: need a properly configured proxy")
	}
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
	"tls-version-max": parseTLSVerMax,
	"proxy-obfs4":     parseProxyOBFS4,
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

func getOptionsFromLines(lines []string, dir string) (*Options, error) {
	s := &Options{}

	// TODO be even more defensive
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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

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
		return nil, err
	}
	if len(lines) != 2 {
		return nil, fmt.Errorf("malformed credentials file")
	}
	if len(lines[0]) == 0 {
		return nil, fmt.Errorf("empty username in creds file")
	}
	if len(lines[1]) == 0 {
		return nil, fmt.Errorf("empty password in creds file")
	}
	return lines, nil
}
