package vpn

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
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

func Test_newDataCipherFromCipherSuite(t *testing.T) {
	type args struct {
		c string
	}
	tests := []struct {
		name    string
		args    args
		want    dataCipher
		wantErr bool
	}{
		{"aes-128-cbc", args{"AES-128-CBC"}, &dataCipherAES{16, "cbc"}, false},
		{"aes-192-cbc", args{"AES-192-CBC"}, &dataCipherAES{24, "cbc"}, false},
		{"aes-256-cbc", args{"AES-256-CBC"}, &dataCipherAES{32, "cbc"}, false},
		{"aes-128-gcm", args{"AES-128-GCM"}, &dataCipherAES{16, "gcm"}, false},
		{"aes-256-gcm", args{"AES-256-GCM"}, &dataCipherAES{32, "gcm"}, false},
		{"bad-256-gcm", args{"AES-512-GCM"}, nil, true},
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
		{"aesOK", args{"aes", 256, "cbc"}, &dataCipherAES{32, "cbc"}, false},
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

// this particular test is basically equivalent to reimplementing the factory, but okay,
// it's somehow useful to catch allowed values.
func Test_newHMACFactory(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name  string
		args  args
		want  func() hash.Hash
		want1 bool
	}{
		{"sha1", args{"sha1"}, sha1.New, true},
		{"sha256", args{"sha256"}, sha256.New, true},
		{"sha512", args{"sha512"}, sha512.New, true},
		{"shabad", args{"sha192"}, nil, false},
	}

	//str := "hello"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := newHMACFactory(tt.args.name)
			if got == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("newHMACFactory() got = %v, want %v", &got, &tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("newHMACFactory() got1 = %v, want %v", got1, tt.want1)
				}
			} else {
				// it is a function factory, so let's get the function to compare
				if !reflect.DeepEqual(got(), tt.want()) {
					t.Errorf("newHMACFactory() got = %v, want %v", &got, &tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("newHMACFactory() got1 = %v, want %v", got1, tt.want1)
				}
			}
		})
	}
}
