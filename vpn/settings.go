package vpn

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

// i'm cutting some corners because serializing this is tedious
const hardcodedOpts = "V1,dev-type tun,link-mtu 1542,tun-mtu 1500,proto UDPv4,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"

// TODO rename to getOptionsAsBytes
func getOptions() []byte {
	return []byte(hardcodedOpts)
}

// not used right now! but the idea is to get configs from here later on if they're not explicitely specified
var defaultSettings = map[string]interface{}{
	"tls-client": true,
	"cipher":     "BF-CBC",
	"auth":       "SHA1",
	"dev-type":   "tun",
	"link-mtu":   "1542",
	"tun-mtu":    "1500",
	"proto":      "UDPv4",
	"comp-lzo":   false,
	"keysize":    "128",
	"key-method": "2",
}

var supportedCiphers = []string{
	"AES-128-CBC",
}

type Settings struct {
	remote   string
	port     string
	cipher   string
	username string
	password string
}

func ParseConfigFile(filePath string) (*Settings, error) {
	lines, err := getLinesFromFile(filePath)
	if err != nil {
		return nil, err
	}
	return getOptionsFromLines(lines)
}

func getOptionsFromLines(lines []string) (*Settings, error) {
	s := &Settings{}

	// TODO be more defensive
	for _, l := range lines {
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
		case "comp-lzo":
			if parts[0] != "no" {
				return nil, fmt.Errorf("comp-lzo: compression not supported, sorry!")
			}
		case "cipher":
			if len(parts) != 1 {
				return nil, fmt.Errorf("cipher expects one arg")
			}
			cipher := parts[0]
			if !hasElement(cipher, supportedCiphers) {
				return nil, fmt.Errorf("unsupported cipher: %s", cipher)
			}
			s.cipher = cipher
		case "auth-user-pass":
			if len(parts) != 1 || !existsFile(parts[0]) {
				return nil, fmt.Errorf("auth-user-pass expects a valid file")
			}
			creds, err := getCredentialsFromFile(parts[0])
			if err != nil {
				return nil, err
			}
			s.username, s.password = creds[0], creds[1]
		default:
			log.Println("WARN unsupported key:", key)
			continue
		}

	}
	log.Println("PARSED", s)
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
