package datachannel

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/session"
)

func Test_decodeEncryptedPayloadAEAD(t *testing.T) {
	state := makeTestingStateAEAD()
	goodEncryptedPayload, _ := hex.DecodeString("00000000b3653a842f2b8a148de26375218fb01d31278ff328ff2fc65c4dbf9eb8e67766")
	goodDecodeIV, _ := hex.DecodeString("000000006868686868686868")
	goodDecodeCipherText, _ := hex.DecodeString("31278ff328ff2fc65c4dbf9eb8e67766b3653a842f2b8a148de26375218fb01d")
	goodDecodeAEAD, _ := hex.DecodeString("4800000000000000")

	type args struct {
		buf     []byte
		session *session.Manager
		state   *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    *encryptedData
		wantErr error
	}{
		{
			"empty buffer should fail",
			args{
				[]byte{},
				makeTestingSession(),
				state,
			},
			&encryptedData{},
			ErrTooShort,
		},
		{
			"too short should fail",
			args{
				bytes.Repeat([]byte{0xff}, 19),
				makeTestingSession(),
				state,
			},
			&encryptedData{},
			ErrTooShort,
		},
		{
			"good decode should not fail",
			args{
				goodEncryptedPayload,
				makeTestingSession(),
				state,
			},
			&encryptedData{
				iv:         goodDecodeIV,
				ciphertext: goodDecodeCipherText,
				aead:       goodDecodeAEAD,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEncryptedPayloadAEAD(log.Log, tt.args.buf, tt.args.session, tt.args.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("decodeEncryptedPayloadAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeEncryptedPayloadAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeEncryptedPayloadNonAEAD(t *testing.T) {

	goodInput, _ := hex.DecodeString("fdf9b069b2e5a637fa7b5c9231166ea96307e4123031323334353637383930313233343581e4878c5eec602c2d2f5a95139c84af")
	iv, _ := hex.DecodeString("30313233343536373839303132333435")
	ciphertext, _ := hex.DecodeString("81e4878c5eec602c2d2f5a95139c84af")

	type args struct {
		buf     []byte
		session *session.Manager
		state   *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    *encryptedData
		wantErr error
	}{
		{
			name: "empty buffer should fail",
			args: args{
				[]byte{},
				makeTestingSession(),
				makeTestingStateNonAEAD(),
			},
			want:    &encryptedData{},
			wantErr: ErrCannotDecode,
		},
		{
			name: "too short buffer should fail",
			args: args{
				bytes.Repeat([]byte{0xff}, 27),
				makeTestingSession(),
				makeTestingStateNonAEAD(),
			},
			want:    &encryptedData{},
			wantErr: ErrCannotDecode,
		},
		{
			name: "good decode",
			args: args{
				goodInput,
				makeTestingSession(),
				makeTestingStateNonAEADReversed(),
			},
			want: &encryptedData{
				iv:         iv,
				ciphertext: ciphertext,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEncryptedPayloadNonAEAD(log.Log, tt.args.buf, tt.args.session, tt.args.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("decodeEncryptedPayloadNonAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got.iv, tt.want.iv) {
				t.Errorf("decodeEncryptedPayloadNonAEAD().iv = %v, want %v", got.iv, tt.want.iv)
			}
			if !bytes.Equal(got.ciphertext, tt.want.ciphertext) {
				t.Errorf("decodeEncryptedPayloadNonAEAD().iv = %v, want %v", got.iv, tt.want.iv)
			}
		})
	}
}
