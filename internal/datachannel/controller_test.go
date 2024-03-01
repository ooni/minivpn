package datachannel

import (
	"bytes"
	"errors"
	"testing"

	"github.com/apex/log"
	"github.com/google/go-cmp/cmp"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
)

func TestNewDataChannelFromOptions(t *testing.T) {
	t.Run("check we can create a data channel", func(t *testing.T) {
		opt := &model.OpenVPNOptions{
			Auth:     "SHA256",
			Cipher:   "AES-128-GCM",
			Compress: model.CompressionEmpty,
		}
		_, err := NewDataChannelFromOptions(log.Log, opt, makeTestingSession())
		if err != nil {
			t.Error("should not fail")
		}
	})
}

func Test_DataChannel_setupKeys(t *testing.T) {
	type fields struct {
		session *session.Manager
		state   *dataChannelState
	}
	type args struct {
		dck *session.DataChannelKey
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "dataChannelKey not ready",
			fields: fields{
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
			},
			args: args{
				dck: &session.DataChannelKey{},
			},
			wantErr: errDataChannelKey,
		},
		{
			name: "good setup",
			fields: fields{
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
			},
			args: args{
				dck: makeTestingDataChannelKey(),
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := &DataChannel{
				sessionManager: tt.fields.session,
				state:          tt.fields.state,
			}
			if err := dc.setupKeys(tt.args.dck); !errors.Is(err, tt.wantErr) {
				t.Errorf("data.SetupKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_DataChannel_writePacket(t *testing.T) {
	type fields struct {
		options *model.OpenVPNOptions
		// session is only used for NonAEAD encryption
		session         *session.Manager
		state           *dataChannelState
		encryptEncodeFn func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error)
	}
	type args struct {
		payload []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *model.Packet
		wantErr error
	}{
		{
			name: "good write with aead encryption should not fail",
			fields: fields{
				options: &model.OpenVPNOptions{Compress: model.CompressionEmpty},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
				encryptEncodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error) {
					return []byte("alles ist garbled gut"), nil
				},
			},
			args: args{
				payload: []byte("hello test"),
			},
			want: &model.Packet{
				Opcode:  model.P_DATA_V2,
				ID:      0,
				ACKs:    []model.PacketID{},
				Payload: []byte("alles ist garbled gut"),
			},
			wantErr: nil,
		},
		{
			name: "good write with non-aead encryption should not fail",
			fields: fields{
				options: &model.OpenVPNOptions{Compress: model.CompressionEmpty},
				session: makeTestingSession(),
				state:   makeTestingStateNonAEAD(),
				encryptEncodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error) {
					return []byte("alles ist garbled gut"), nil
				},
			},
			args: args{
				payload: []byte("hello test"),
			},
			want: &model.Packet{
				Opcode:  model.P_DATA_V2,
				ID:      0,
				ACKs:    []model.PacketID{},
				Payload: []byte("alles ist garbled gut"),
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := &DataChannel{
				options:         tt.fields.options,
				sessionManager:  tt.fields.session,
				state:           tt.fields.state,
				encryptEncodeFn: tt.fields.encryptEncodeFn,
			}
			got, err := dc.writePacket(tt.args.payload)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.WritePacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func Test_DataChannel_deadPacket(t *testing.T) {

	goodMockDecodeFn := func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error) {
		d := &encryptedData{
			iv:         []byte{0xee},
			ciphertext: []byte("garbledpayload"),
			aead:       []byte{0xff},
		}
		return d, nil
	}

	goodMockDecryptFn := func([]byte, *encryptedData) ([]byte, error) {
		return []byte("alles ist gut"), nil
	}

	type fields struct {
		options   *model.OpenVPNOptions
		state     *dataChannelState
		decodeFn  func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error)
		decryptFn func([]byte, *encryptedData) ([]byte, error)
	}
	type args struct {
		p *model.Packet
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "good decrypt using mocked decrypt fn and decode fn",
			fields: fields{
				options:   makeTestingOptions(t, "AES-128-GCM", "sha1"),
				state:     makeTestingStateAEAD(),
				decryptFn: goodMockDecryptFn,
				decodeFn:  goodMockDecodeFn,
			},
			args: args{
				&model.Packet{
					Opcode:  model.P_DATA_V1,
					Payload: []byte("garbled")},
			},
			want:    []byte("alles ist gut"),
			wantErr: nil,
		},
		// TODO panic when call to DecodeEncryptedPayload
		// TODO error if empty payload
		// TODO make sure decompress fn is called?
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DataChannel{
				options:   tt.fields.options,
				state:     tt.fields.state,
				decryptFn: tt.fields.decryptFn,
				decodeFn:  tt.fields.decodeFn,
			}
			got, err := d.readPacket(tt.args.p)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.ReadPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func Test_Data_decrypt(t *testing.T) {

	goodMockDecryptFn := func([]byte, *encryptedData) ([]byte, error) {
		return []byte("alles ist gut"), nil
	}

	failingMockDecryptFn := func([]byte, *encryptedData) ([]byte, error) {
		return []byte{}, ErrCannotDecrypt
	}

	type fields struct {
		options         *model.OpenVPNOptions
		session         *session.Manager
		state           *dataChannelState
		decryptFn       func([]byte, *encryptedData) ([]byte, error)
		decodeFn        func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error)
		encryptEncodeFn func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error)
	}
	type args struct {
		encrypted []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "empty output in decode does fail",
			fields: fields{
				options: &model.OpenVPNOptions{},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
				decodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error) {
					return &encryptedData{}, nil
				},
				decryptFn: goodMockDecryptFn,
			},
			args: args{
				encrypted: bytes.Repeat([]byte{0x0a}, 20),
			},
			want:    []byte{},
			wantErr: ErrCannotDecrypt,
		},
		{
			name: "empty encrypted input does fail",
			fields: fields{
				options: &model.OpenVPNOptions{},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
				decodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error) {
					return &encryptedData{}, nil
				},
				decryptFn: goodMockDecryptFn,
			},
			args: args{
				encrypted: []byte{},
			},
			want:    []byte{},
			wantErr: ErrCannotDecrypt,
		},
		{
			name: "error in decrypt propagates",
			fields: fields{
				options: &model.OpenVPNOptions{},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
				decodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error) {
					return &encryptedData{}, nil
				},
				encryptEncodeFn: nil,
				decryptFn:       failingMockDecryptFn,
			},
			args: args{
				encrypted: []byte{},
			},
			want:    []byte{},
			wantErr: ErrCannotDecrypt,
		},
		{
			name: "good decrypt returns expected output",
			fields: fields{
				options: &model.OpenVPNOptions{},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
				decodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error) {
					return &encryptedData{ciphertext: []byte("asdf")}, nil
				},
				decryptFn: goodMockDecryptFn,
			},
			args: args{
				encrypted: []byte{},
			},
			want:    []byte("alles ist gut"),
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DataChannel{
				options:         tt.fields.options,
				sessionManager:  tt.fields.session,
				state:           tt.fields.state,
				decodeFn:        tt.fields.decodeFn,
				decryptFn:       tt.fields.decryptFn,
				encryptEncodeFn: tt.fields.encryptEncodeFn,
			}
			got, err := d.decrypt(tt.args.encrypted)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}
