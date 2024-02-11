package datachannel

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"log"
	"reflect"
	"testing"

	"github.com/ooni/minivpn/internal/bytesx"
)

func Test_dataCipherAES_decrypt(t *testing.T) {
	key := bytes.Repeat([]byte("A"), 64)
	iv12, _ := hex.DecodeString("000000006868686868686868")
	iv16, _ := hex.DecodeString("00000000686868686868686865656565")
	ciphertextGCM, _ := hex.DecodeString("a949df311c57ec762428a7ba98d1d0d8213134925bf1cd2cb4ab4ea9066c569b0579")
	ciphertextCBC, _ := hex.DecodeString("f908ff8dedbe4e2097c992c67e603d25606c76a460cd785503cf0a2a9e6ec961")

	type fields struct {
		ksb  int
		mode cipherMode
	}
	type args struct {
		key  []byte
		data *encryptedData
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "good decrypt gcm",
			fields: fields{
				ksb:  16,
				mode: cipherModeGCM,
			},
			args: args{
				key: key,
				data: &encryptedData{
					iv:         iv12,
					ciphertext: ciphertextGCM,
					aead:       []byte{0x00, 0x01, 0x02, 0x03},
				},
			},
			want:    []byte("this test is green"),
			wantErr: nil,
		},
		{
			name: "iv too short gcm",
			fields: fields{
				ksb:  16,
				mode: cipherModeGCM,
			},
			args: args{
				key: key,
				data: &encryptedData{
					iv:         []byte{0x00},
					ciphertext: ciphertextGCM,
					aead:       []byte{0x00, 0x01, 0x02, 0x03},
				},
			},
			want:    nil,
			wantErr: ErrCannotDecrypt,
		},
		{
			name: "good decrypt cbc",
			fields: fields{
				ksb:  16,
				mode: cipherModeCBC,
			},
			args: args{
				key: key,
				data: &encryptedData{
					iv:         iv16,
					ciphertext: ciphertextCBC,
					aead:       []byte{0x00, 0x01, 0x02, 0x03},
				},
			},
			want:    []byte("this test is green"),
			wantErr: nil,
		},
		{
			name: "iv too short cbc",
			fields: fields{
				ksb:  16,
				mode: cipherModeGCM,
			},
			args: args{
				key: key,
				data: &encryptedData{
					iv:         []byte{0x00},
					ciphertext: ciphertextGCM,
					aead:       []byte{0x00, 0x01, 0x02, 0x03},
				},
			},
			want:    []byte{},
			wantErr: ErrCannotDecrypt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &dataCipherAES{
				ksb:  tt.fields.ksb,
				mode: tt.fields.mode,
			}
			got, err := a.decrypt(tt.args.key, tt.args.data)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("dataCipherAES.decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("dataCipherAES.decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func doPaddingForTest(payload []byte, blockSize int) []byte {
	padded, _ := bytesx.BytesPadPKCS7(payload, blockSize)
	return padded
}

func Test_dataCipherAES_encrypt(t *testing.T) {
	key := bytes.Repeat([]byte("A"), 64)
	iv12, _ := hex.DecodeString("000000006868686868686868")
	iv16, _ := hex.DecodeString("00000000686868686868686865656565")

	ciphertextGCM, _ := hex.DecodeString("a949df311c57ec762428a7ba98d1d0d8213134925bf1cd2cb4ab4ea9066c569b0579")
	ciphertextCBC, _ := hex.DecodeString("f908ff8dedbe4e2097c992c67e603d25606c76a460cd785503cf0a2a9e6ec961")

	type fields struct {
		ksb  int
		mode cipherMode
	}
	type args struct {
		key  []byte
		data *plaintextData
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "good encrypt aes-128-gcm",
			fields: fields{
				ksb:  16,
				mode: cipherModeGCM,
			},
			args: args{
				key: key,
				data: &plaintextData{
					iv:        iv12,
					plaintext: []byte("this test is green"),
					aead:      []byte{0x00, 0x01, 0x02, 0x03},
				},
			},
			want:    ciphertextGCM,
			wantErr: nil,
		},
		{
			name: "iv too short aes-128-gcm",
			fields: fields{
				ksb:  16,
				mode: cipherModeGCM,
			},
			args: args{
				key: key,
				data: &plaintextData{
					iv:        []byte{0x00},
					plaintext: []byte("should fail"),
					aead:      []byte{0x00, 0x01, 0x02, 0x03},
				},
			},
			want:    []byte(""),
			wantErr: ErrCannotEncrypt,
		},
		{
			name: "iv too short aes-128-cbc",
			fields: fields{
				ksb:  16,
				mode: cipherModeCBC,
			},
			args: args{
				key: key,
				data: &plaintextData{
					iv:        iv12,
					plaintext: []byte("should fail"),
				},
			},
			want:    []byte(""),
			wantErr: ErrCannotEncrypt,
		},
		{
			name: "bad padding aes-128-cbc",
			fields: fields{
				ksb:  16,
				mode: cipherModeCBC,
			},
			args: args{
				key: key,
				data: &plaintextData{
					iv:        iv16,
					plaintext: []byte("should fail"),
				},
			},
			want:    []byte(""),
			wantErr: ErrCannotEncrypt,
		},
		{
			name: "good encrypt aes-128-cbc",
			fields: fields{
				ksb:  16,
				mode: cipherModeCBC,
			},
			args: args{
				key: key,
				data: &plaintextData{
					iv:        iv16,
					plaintext: doPaddingForTest([]byte("this test is green"), 16),
				},
			},
			want:    ciphertextCBC,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &dataCipherAES{
				ksb:  tt.fields.ksb,
				mode: tt.fields.mode,
			}
			got, err := a.encrypt(tt.args.key, tt.args.data)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("dataCipherAES.encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				log.Println(hex.EncodeToString(got))

				t.Errorf("dataCipherAES.encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dataCipher(t *testing.T) {
	t.Run("aes-128-cbc", func(t *testing.T) {
		if _, err := newDataCipher("aes", 128, "cbc"); err != nil {
			t.Errorf("failed for aes-128-cbc")
		}
	})
	t.Run("bad-128-cbc should fail", func(t *testing.T) {
		if _, err := newDataCipher("bad", 128, "cbc"); err == nil {
			t.Errorf("bad cipher should fail")
		}
	})
	t.Run("aes-128-bad should fail", func(t *testing.T) {
		if _, err := newDataCipher("aes", 128, "bad"); err == nil {
			t.Errorf("Should fail with bad mode")
		}
	})
	t.Run("aes-1024-cbc should fail", func(t *testing.T) {
		if _, err := newDataCipher("aes", 1024, "cbc"); err == nil {
			t.Errorf("bad key size should fail")
		}
	})
	t.Run("aes-8-cbc should fail", func(t *testing.T) {
		if _, err := newDataCipher("aes", 8, "cbc"); err == nil {
			t.Errorf("Should fail with bad key size")
		}
	})
}

func Test_newDataCipher(t *testing.T) {
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
		{
			"aesOK",
			args{"aes", 256, "cbc"},
			&dataCipherAES{32, "cbc"},
			false,
		},
		{
			"badCipher",
			args{"blowfish", 256, "cbc"},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newDataCipher(tt.args.name, tt.args.bits, tt.args.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("newDataCipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newDataCipher() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newDataCipherFromCipherSuite(t *testing.T) {
	type args struct {
		ciphersuite string
	}
	tests := []struct {
		name    string
		args    args
		want    dataCipher
		wantErr error
	}{
		{"aes-128-cbc", args{"AES-128-CBC"}, &dataCipherAES{16, "cbc"}, nil},
		{"aes-192-cbc", args{"AES-192-CBC"}, &dataCipherAES{24, "cbc"}, nil},
		{"aes-256-cbc", args{"AES-256-CBC"}, &dataCipherAES{32, "cbc"}, nil},
		{"aes-128-gcm", args{"AES-128-GCM"}, &dataCipherAES{16, "gcm"}, nil},
		{"aes-256-gcm", args{"AES-256-GCM"}, &dataCipherAES{32, "gcm"}, nil},
		{"bad-256-gcm", args{"AES-512-GCM"}, nil, ErrUnsupportedCipher},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newDataCipherFromCipherSuite(tt.args.ciphersuite)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("newCipherFromCipherSuite() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCipherFromCipherSuite() = %v, want %v", got, tt.want)
			}
		})
	}
}

// this particular test is basically equivalent to reimplementing the factory, but still
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

func TestPrf(t *testing.T) {
	expected := []byte{
		0x67, 0x18, 0x7c, 0x52, 0xac, 0xd2, 0x4d, 0x95,
		0x9a, 0x55, 0xd3, 0x1c, 0xdb, 0x97, 0x80, 0x11}
	secret := []byte("secret")
	label := []byte("master key")
	cseed := []byte("aaa")
	sseed := []byte("bbb")
	out := prf(secret, label, cseed, sseed, []byte{}, []byte{}, 16)
	if !bytes.Equal(out, expected) {
		t.Errorf("Bad output in prf call: %v", out)
	}
}
