package vpn

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
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

// TODO this should inform the selection of ciphers in initTLS,
// but need to check the options too.
var supportedTLSCipher = []string{
	// DHE-RSA-AES128-SHA -> riseup legacy; this is problematic because go
	// tls doesn't implement finite DH.
	// TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
	// TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
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

// i'm cutting some corners because serializing this is tedious
// FIXME i'm still debugging compression frames to get riseup/calyx working
const hardcodedOpts = "V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-client"

func getOptionsAsBytes() []byte {
	// FIXME testing hack - this needs to be a method on Options
	o := string(hardcodedOpts)
	if os.Getenv("COMP_STUB") == "1" {
		o = o + ",compress stub"
	} else if os.Getenv("NOLZO_COMP") == "1" {
		o = o + ",lzo-comp no"
	} else {
		//nothing
	}
	log.Println("Local opts: ", o)
	return []byte(o)
}

// not used right now! but the idea is to get configs from here later on if
// they're not explicitely specified
// and serialize  this directly if nothing else is provided
var defaultOptions = map[string]interface{}{
	"tls-client": true,
	"cipher":     "AES-128-CBC",
	"auth":       "SHA1",
	"dev-type":   "tun",
	"link-mtu":   "1542",
	"tun-mtu":    "1500",
	"proto":      "UDPv4",
	"comp-lzo":   false,
	"keysize":    "128",
	"key-method": "2",
}

type Options struct {
	remote   string
	port     string
	username string
	password string
	ca       string
	cert     string
	key      string
	compress string

	cipher string
	auth   string
}

func ParseConfigFile(filePath string) (*Options, error) {
	lines, err := getLinesFromFile(filePath)
	if err != nil {
		return nil, err
	}
	return getOptionsFromLines(lines)
}

func getOptionsFromLines(lines []string) (*Options, error) {
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
			s.remote = parts[0]
			s.port = parts[1]
		case "cipher":
			if len(parts) != 1 {
				return nil, fmt.Errorf("cipher expects one arg")
			}
			cipher := parts[0]
			if !hasElement(cipher, supportedCiphers) {
				return nil, fmt.Errorf("unsupported cipher: %s", cipher)
			}
			s.cipher = cipher
		case "auth":
			if len(parts) != 1 {
				return nil, fmt.Errorf("invalid auth entry")
			}
			auth := parts[0]
			if !hasElement(auth, supportedAuth) {
				return nil, fmt.Errorf("unsupported auth: %s", auth)
			}
			s.auth = auth
		case "auth-user-pass":
			if len(parts) != 1 || !existsFile(parts[0]) {
				return nil, fmt.Errorf("auth-user-pass expects a valid file")
			}
			creds, err := getCredentialsFromFile(parts[0])
			if err != nil {
				return nil, err
			}
			s.username, s.password = creds[0], creds[1]
		case "ca":
			if len(parts) != 1 || !existsFile(parts[0]) {
				return nil, fmt.Errorf("ca expects a valid file")
			}
			s.ca = parts[0]
		case "cert":
			if len(parts) != 1 || !existsFile(parts[0]) {
				return nil, fmt.Errorf("cert expects a valid file")
			}
			s.cert = parts[0]
		case "key":
			if len(parts) != 1 || !existsFile(parts[0]) {
				return nil, fmt.Errorf("key expects a valid file")
			}
			s.key = parts[0]
		case "compress":
			if len(parts) != 0 {
				return nil, fmt.Errorf("only compress: empty option supported")
			}
			s.compress = "empty"
		case "comp-lzo":
			if parts[0] != "no" {
				return nil, fmt.Errorf("comp-lzo: compression not supported, sorry!")
			}
			s.compress = "lzo-no"
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
