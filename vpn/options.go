package vpn

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

// TODO this should inform the selection of ciphers in initTLS
var supportedTLSCipher = []string{
	// DHE-RSA-AES128-SHA -> riseup legacy; this is problematic because go
	// tls doesn't implement finite DH.
	// TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
	// TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
}

// Options make all the relevant configuration options accessible to the
// different modules that need it.
type Options struct {
	Remote   string
	Port     string
	Proto    string
	Username string
	Password string
	Ca       string
	Cert     string
	Key      string
	Compress string
	Cipher   string
	Auth     string
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

const clientOptions = "V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher %s,auth %s,keysize %s,key-method 2,tls-client"

func getOptionsAsBytes(opts *Options) []byte {
	keysize := strings.Split(opts.Cipher, "-")[1]
	o := fmt.Sprintf(
		clientOptions,
		opts.Cipher, opts.Auth, keysize)
	if opts.Compress == "stub" {
		o = o + ",compress stub"
	} else if opts.Compress == "lzo-no" {
		o = o + ",lzo-comp no"
	}
	log.Println("Local opts: ", o)
	return []byte(o)
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
		var key string
		var parts []string
		var e error
		if len(p) == 1 {
			key = p[0]
		} else {
			key, parts = p[0], p[1:]
		}

		switch key {
		case "remote":
			if len(parts) != 2 {
				return nil, fmt.Errorf("remote needs two args")
			}
			s.Remote = parts[0]
			s.Port = parts[1]
		case "cipher":
			if len(parts) != 1 {
				return nil, fmt.Errorf("cipher expects one arg")
			}
			cipher := parts[0]
			if !hasElement(cipher, supportedCiphers) {
				return nil, fmt.Errorf("unsupported cipher: %s", cipher)
			}
			s.Cipher = cipher
		case "auth":
			if len(parts) != 1 {
				return nil, fmt.Errorf("invalid auth entry")
			}
			auth := parts[0]
			if !hasElement(auth, supportedAuth) {
				return nil, fmt.Errorf("unsupported auth: %s", auth)
			}
			s.Auth = auth
		case "auth-user-pass":
			if len(parts) != 1 || !existsFile(parts[0]) {
				return nil, fmt.Errorf("auth-user-pass expects a valid file")
			}
			creds, err := getCredentialsFromFile(parts[0])
			if err != nil {
				return nil, err
			}
			s.Username, s.Password = creds[0], creds[1]
		case "ca":
			e = fmt.Errorf("ca expects a valid file")
			if len(parts) != 1 {
				return nil, e
			}
			ca := filepath.Join(dir, parts[0])
			if !existsFile(ca) {
				return nil, e
			}
			s.Ca = ca

		case "cert":
			e = fmt.Errorf("cert expects a valid file")
			if len(parts) != 1 {
				return nil, e
			}
			cert := filepath.Join(dir, parts[0])
			if !existsFile(cert) {
				return nil, e
			}
			s.Cert = cert

		case "key":
			e = fmt.Errorf("key expects a valid file")
			if len(parts) != 1 {
				return nil, e
			}
			key := filepath.Join(dir, parts[0])
			if !existsFile(key) {
				return nil, e
			}
			s.Key = key
		case "compress":
			if len(parts) > 1 {
				return nil, fmt.Errorf("compress: only empty/stub options supported")
			}
			if len(parts) == 0 {
				s.Compress = "empty"
				continue
			}
			if parts[0] == "stub" {
				s.Compress = "stub"
			}
		case "comp-lzo":
			if parts[0] != "no" {
				return nil, fmt.Errorf("comp-lzo: compression not supported, sorry")
			}
			s.Compress = "lzo-no"
		default:
			log.Println("WARN unsupported key:", key)
			continue
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
