package vpn

import (
	"reflect"
	"testing"
)

func TestDataCipherAES(t *testing.T) {
	_, err := newDataCipher("aes", 128, "cbc")
	if err != nil {
		t.Errorf("Cannot instantiate aes-128-cbc")
	}
}

func TestBadCipher(t *testing.T) {
	_, err := newDataCipher("bad", 128, "cbc")
	if err == nil {
		t.Errorf("Should fail with bad cipher")
	}
}

func TestBadMode(t *testing.T) {
	_, err := newDataCipher("aes", 128, "bad")
	if err == nil {
		t.Errorf("Should fail with bad mode")
	}
}

func TestBadKeySize(t *testing.T) {
	_, err := newDataCipher("aes", 1024, "cbc")
	if err == nil {
		t.Errorf("Should fail with bad key size")
	}
	_, err = newDataCipher("aes", 8, "cbc")
	if err == nil {
		t.Errorf("Should fail with bad key size")
	}
}

/*
func Test_getHMAC(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name  string
		args  args
		want  func() hash.Hash
		want1 bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getHMAC(tt.args.name)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getHMAC() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getHMAC() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
*/

func Test_newCipherFromCipherSuite(t *testing.T) {
	type args struct {
		c string
	}
	tests := []struct {
		name    string
		args    args
		want    dataCipher
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newDataCipherFromCipherSuite(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("newCipherFromCipherSuite() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCipherFromCipherSuite() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newCipher(t *testing.T) {
	type args struct {
		name cipherName
		bits int
		mode cipherMode
	}
	tests := []struct {
		name    string
		args    args
		want    dataCipher
		wantErr bool
	}{
		{"aesOK", args{"aes", 256, "cbc"}, &dataCipherAES{256 / 8, "cbc"}, false},
		{"badCipher", args{"blowfish", 256, "cbc"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newDataCipher(tt.args.name, tt.args.bits, tt.args.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("newCipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCipher() = %v, want %v", got, tt.want)
			}
		})
	}
}
