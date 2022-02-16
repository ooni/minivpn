package vpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
)

type Cipher interface {
	KeySizeBytes() int
	IsAEAD() bool
	BlockSize() int
	Encrypt(key, iv, plaintext, ad []byte) ([]byte, error)
	Decrypt(key, iv, ciphertext, ad []byte) ([]byte, error)
}

type AESCipher struct {
	keySizeBits int
	mode        string
}

func (c *AESCipher) KeySizeBytes() int {
	return c.keySizeBits / 8
}

func (c *AESCipher) IsAEAD() bool {
	if c.mode == "cbc" {
		return false
	}
	return true
}

func (c *AESCipher) BlockSize() int {
	if c.mode == "cbc" || c.mode == "gcm" {
		return 16
	}
	return 0
}

// data is optional, and only used in AEAD modes
func (c *AESCipher) Decrypt(key, iv, ciphertext, ad []byte) ([]byte, error) {
	k := key[:c.KeySizeBytes()]

	var block cipher.Block
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	//var plaintext []byte
	var mode cipher.BlockMode

	switch c.mode {
	case "cbc":
		iv_ := iv[:block.BlockSize()]
		mode = cipher.NewCBCDecrypter(block, iv_)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)
		plaintext = unpadText(plaintext)
		padLen := len(ciphertext) - len(plaintext)
		if padLen > block.BlockSize() || padLen > len(plaintext) {
			log.Fatal("Padding error")
		}
		return plaintext, nil
	case "gcm":
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		log.Println(">> GCM decrypt")
		log.Println("iv", len(iv), "CT", len(ciphertext), "ad", len(ad))
		log.Println("AD:", ad)
		plaintext, err := aesGCM.Open(nil, iv, ciphertext, ad)
		if err != nil {
			log.Println(">>> decryption failed!")
			return nil, err
		}
		return plaintext, nil
	default:
		log.Fatal("only CBC or GCM modes allowed")
	}

	if c.mode == "cbc" {
	}
	return nil, nil
}

// data is optional, and only used in AEAD modes
func (c *AESCipher) Encrypt(key, iv, plaintext, ad []byte) ([]byte, error) {
	k := key[:c.KeySizeBytes()]
	iv_ := iv[:c.BlockSize()]

	var block cipher.Block
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte
	var mode cipher.BlockMode

	switch c.mode {
	case "cbc":
		mode = cipher.NewCBCEncrypter(block, iv_)
		ciphertext = make([]byte, len(plaintext))
		mode.CryptBlocks(ciphertext, plaintext)
	case "gcm":
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
		log.Println("PT->", hex.EncodeToString(plaintext))
		log.Println("CT->", hex.EncodeToString(ciphertext))
	default:
		log.Fatal("only CBC or GCM  modes allowed")
	}
	return ciphertext, nil
}

func newCipherFromCipherSuite(c string) (Cipher, error) {
	switch c {
	case "AES-128-CBC":
		return newCipher("aes", 128, "cbc")
	case "AES-192-CBC":
		return newCipher("aes", 192, "cbc")
	case "AES-256-CBC":
		return newCipher("aes", 256, "cbc")
	case "AES-128-GCM":
		return newCipher("aes", 128, "gcm")
	default:
		break
	}
	return nil, fmt.Errorf("unsupported cipher")
}

func newCipher(name string, bits int, mode string) (Cipher, error) {
	if bits%8 != 0 || bits > 512 || bits < 64 {
		return nil, fmt.Errorf("invalid key size: %d", bits)
	}
	switch name {
	case "aes":
		break
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", name)
	}
	switch mode {
	case "cbc":
		break
	case "gcm":
		break
	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}
	return &AESCipher{bits, mode}, nil
}

func getHMAC(name string) func() hash.Hash {
	switch name {
	case "sha1":
		return sha1.New
	case "sha256":
		return sha256.New
	case "sha512":
		return sha512.New
	default:
		return nil
	}
}

// pkcs7 unpadding
func unpadText(buf []byte) []byte {
	padding := int(buf[len(buf)-1])
	return buf[:len(buf)-padding]
}

// pkcs7 padding
func padText(buf []byte, bs int) []byte {
	padding := bs - len(buf)%bs
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(buf, padtext...)
}
