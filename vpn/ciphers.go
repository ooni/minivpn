package vpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"hash"
	"log"
)

type Cipher interface {
	BlockSize() int
	IsAEAD() bool
	Encrypt(key, iv, plaintext []byte) ([]byte, error)
	Decrypt(key, iv, ciphertext []byte) ([]byte, error)
}

type AESCipher struct {
	keySizeBits int
	mode        string
}

func (c *AESCipher) BlockSize() int {
	return c.keySizeBits / 8
}

func (c *AESCipher) IsAEAD() bool {
	return false
}

func (c *AESCipher) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	k := key[:c.BlockSize()]
	var block cipher.Block
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	var mode cipher.BlockMode
	if c.mode != "cbc" {
		log.Fatal("no other modes implemented now")
	}
	mode = cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	plaintext = unpad(plaintext)
	padLen := len(ciphertext) - len(plaintext)
	if padLen > c.BlockSize() || padLen > len(plaintext) {
		log.Fatal("Padding error")
	}
	return plaintext, nil
}

func (c *AESCipher) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	/*
	   cipher = Cipher(algorithms.AES(key[: self.keysize_bytes]), mode=modes.CBC(iv))
	   encryptor = cipher.encryptor()
	   return cipher.encrypt(plaintext)
	*/

	return nil, nil
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
	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}
	return &AESCipher{bits, mode}, nil
}

func getHMAC(name string) func() hash.Hash {
	switch name {
	case "sha1":
		return sha1.New
	default:
		return nil
	}
}

func unpad(buf []byte) []byte {
	padding := int(buf[len(buf)-1])
	return buf[:len(buf)-padding]
}
