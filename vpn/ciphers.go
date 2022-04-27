package vpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log"
)

// TODO see if it's feasible to replace in part with some stdlib interfaces
// because this might be redundant

var (
	cbcMode  = "cbc"
	gcmMode  = "gcm"
	aesLabel = "aes"
)

type dataCipher interface {
	keySizeBytes() int
	isAEAD() bool
	blockSize() int
	encrypt(key, iv, plaintext, ad []byte) ([]byte, error)
	decrypt(key, iv, ciphertext, ad []byte) ([]byte, error)
}

type aesCipher struct {
	keySizeBits int
	mode        string
}

func (a *aesCipher) keySizeBytes() int {
	return a.keySizeBits / 8
}

func (a *aesCipher) isAEAD() bool {
	if a.mode == cbcMode {
		return false
	}
	return true
}

func (a *aesCipher) blockSize() int {
	if a.mode == cbcMode || a.mode == gcmMode {
		return 16
	}
	return 0
}

// decrypt tries to decrypt the ciphertext. ad is optional, and only used in AEAD modes.
func (a *aesCipher) decrypt(key, iv, ciphertext, ad []byte) ([]byte, error) {
	k := key[:a.keySizeBytes()] // use stdlib

	var block cipher.Block
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	var mode cipher.BlockMode

	switch a.mode {
	case cbcMode:
		i := iv[:block.BlockSize()]
		mode = cipher.NewCBCDecrypter(block, i)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)
		plaintext = unpadText(plaintext)

		padLen := len(ciphertext) - len(plaintext)
		if padLen > block.BlockSize() || padLen > len(plaintext) {
			log.Fatal("Padding error")
		}
		return plaintext, nil
	case gcmMode:
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		plaintext, err := aesGCM.Open(nil, iv, ciphertext, ad)

		if err != nil {
			log.Println("gdm decryption failed:", err.Error())
			log.Println("dump begins----")
			log.Printf("%x\n", ciphertext)
			log.Println("len:", len(ciphertext))
			log.Printf("ad: %x\n", ad)
			log.Println("dump ends------")
			return nil, err
		}
		return plaintext, nil
	default:
		log.Fatal("only CBC or GCM modes allowed")
	}

	return nil, nil
}

// encrypt encrypts the plaintext. ad is optional, and only used in AEAD modes
func (a *aesCipher) encrypt(key, iv, plaintext, ad []byte) ([]byte, error) {
	k := key[:a.keySizeBytes()] // get from stdlib
	i := iv[:a.blockSize()]

	var block cipher.Block
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte
	var mode cipher.BlockMode

	switch a.mode {
	case cbcMode:
		mode = cipher.NewCBCEncrypter(block, i)
		ciphertext = make([]byte, len(plaintext))
		mode.CryptBlocks(ciphertext, plaintext)
	case gcmMode:
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		// in GCM mode, the iv consist of the 32-bit packet counter
		// followed by data from the HMAC key. The HMAC key can be used
		// as iv, since in GCM mode the HMAC key is not used for the
		// HMAC. The packet counter may not roll over within a single
		// TLS session. This results in a unique IV for each packet, as
		// required by GCM.
		ciphertext = aesGCM.Seal(nil, iv, plaintext, ad)
	default:
		log.Fatal("only CBC or GCM  modes allowed")
	}
	return ciphertext, nil
}

func newCipherFromCipherSuite(c string) (dataCipher, error) {
	switch c {
	case "AES-128-CBC":
		return newCipher(aesLabel, 128, cbcMode)
	case "AES-192-CBC":
		return newCipher(aesLabel, 192, cbcMode)
	case "AES-256-CBC":
		return newCipher(aesLabel, 256, cbcMode)
	case "AES-128-GCM":
		return newCipher(aesLabel, 128, gcmMode)
	case "AES-256-GCM":
		return newCipher(aesLabel, 256, gcmMode)
	default:
		break
	}
	return nil, fmt.Errorf("unsupported cipher")
}

func newCipher(name string, bits int, mode string) (dataCipher, error) {
	if bits%8 != 0 || bits > 512 || bits < 64 {
		return nil, fmt.Errorf("invalid key size: %d", bits)
	}
	switch name {
	case aesLabel:
		break
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", name)
	}
	switch mode {
	case cbcMode:
		break
	case gcmMode:
		break
	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}
	return &aesCipher{bits, mode}, nil
}

// getHMAC accepts a label coming from an OpenVPN auth label, and returns two
// values: a function that will return a Hash implementation, and a boolean
// indicating if the operation was successful.
func getHMAC(name string) (func() hash.Hash, bool) {
	switch name {
	case "sha1":
		return sha1.New, true
	case "sha256":
		return sha256.New, true
	case "sha512":
		return sha512.New, true
	default:
		return nil, false
	}
}

// unpadText does pkcs7 unpadding of a byte array.
func unpadText(buf []byte) []byte {
	padding := int(buf[len(buf)-1])
	return buf[:len(buf)-padding]
}

// padText does pkcs7 padding of a byte array.
func padText(buf []byte, bs int) []byte {
	padding := bs - len(buf)%bs
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(buf, padtext...)
}
