package vpn

import (
	//"crypto/aes"
	//"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
)

type Cipher interface {
	BlockSize() int
	IsAEAD() bool
	Encrypt(key, iv, plaintext []byte) error
	Decrypt(key, iv, ciphertext []byte) error
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

func (c *AESCipher) Encrypt(key, iv, plaintext []byte) error {
	return nil
}

func (c *AESCipher) Decrypt(key, iv, ciphertext []byte) error {
	return nil
}

// FIXME -- add tests for encryptor / decryptor

/*
   def encrypt(self, key, iv, plaintext):
       cipher = Cipher(algorithms.AES(key[: self.keysize_bytes]), mode=modes.CBC(iv))
       encryptor = cipher.encryptor()
       return cipher.encrypt(plaintext)

   def decrypt(self, key, iv, ciphertext):
       cipher = Cipher(algorithms.AES(key[: self.keysize_bytes]), mode=modes.CBC(iv))
       decryptor = cipher.decryptor()
       return decryptor.decrypt(ciphertext)
*/

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
