package vpn

import (
	"testing"
)

func TestAESCipher(t *testing.T) {
	_, err := newCipher("aes", 128, "cbc")
	if err != nil {
		t.Errorf("Cannot instantiate aes-128-cbc")
	}

}

func TestBadCipher(t *testing.T) {
	_, err := newCipher("bad", 128, "cbc")
	if err == nil {
		t.Errorf("Should fail with bad cipher")
	}
}

func TestBadMode(t *testing.T) {
	_, err := newCipher("aes", 128, "bad")
	if err == nil {
		t.Errorf("Should fail with bad mode")
	}
}

func TestBadKeySize(t *testing.T) {
	_, err := newCipher("aes", 1024, "cbc")
	if err == nil {
		t.Errorf("Should fail with bad key size")
	}
	_, err = newCipher("aes", 8, "cbc")
	if err == nil {
		t.Errorf("Should fail with bad key size")
	}
}
