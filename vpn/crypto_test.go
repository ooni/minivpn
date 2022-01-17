package vpn

import (
	"testing"
)

func TestPrf(t *testing.T) {
	expected := []byte{
		0x67, 0x18, 0x7c, 0x52, 0xac, 0xd2, 0x4d, 0x95,
		0x9a, 0x55, 0xd3, 0x1c, 0xdb, 0x97, 0x80, 0x11}
	secret := []byte("secret")
	label := []byte("master key")
	cseed := []byte("aaa")
	sseed := []byte("bbb")
	out := prf(secret, label, cseed, sseed, []byte{}, []byte{}, 16)
	if !areBytesEqual(out, expected) {
		t.Errorf("Bad output in prf call: %v", out)
	}
}
