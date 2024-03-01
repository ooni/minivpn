package datachannel

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/apex/log"
	"github.com/google/go-cmp/cmp"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
)

func Test_encryptAndEncodePayloadAEAD(t *testing.T) {

	state := makeTestingStateAEAD()
	padded, _ := doPadding([]byte("hello go tests"), "", state.dataCipher.blockSize())

	goodEncryptedPayload, _ := hex.DecodeString("48000000000000016ac571106b388f465849c92cb509dfc694c686a0734b92c443b193d579efe1b8")

	type args struct {
		logger  model.Logger
		padded  []byte
		session *session.Manager
		state   *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			"good encrypt does not fail",
			args{log.Log, padded, makeTestingSession(), state},
			goodEncryptedPayload,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptAndEncodePayloadAEAD(tt.args.logger, tt.args.padded, tt.args.session, tt.args.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("encryptAndEncodePayloadAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				fmt.Printf("%x", got)
				t.Errorf("encryptAndEncodePayloadAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encryptAndEncodePayloadNonAEAD(t *testing.T) {

	padded16 := bytes.Repeat([]byte{0xff}, 16)
	padded15 := bytes.Repeat([]byte{0xff}, 15)
	rnd16 := "0123456789012345"
	rnd32 := "01234567890123456789012345678901"

	// including OP32 header + peerid (v2)
	goodEncrypted, _ := hex.DecodeString("48000000fdf9b069b2e5a637fa7b5c9231166ea96307e4123031323334353637383930313233343581e4878c5eec602c2d2f5a95139c84af")

	// we replace the global random function that is used for the iv in, e.g., CBC mode.
	genRandomFn = func(i int) ([]byte, error) {
		switch i {
		case 16:
			return []byte(rnd16), nil
		default:
			return []byte(rnd32), nil
		}
	}

	type args struct {
		logger  model.Logger
		padded  []byte
		session *session.Manager
		state   *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "good encrypt",
			args: args{
				logger:  log.Log,
				padded:  padded16,
				session: makeTestingSession(),
				state:   makeTestingStateNonAEAD()},
			want:    goodEncrypted,
			wantErr: nil,
		},
		{
			name: "badly padded input should fail",
			args: args{
				logger:  log.Log,
				padded:  padded15,
				session: makeTestingSession(),
				state:   makeTestingStateNonAEAD()},
			want:    nil,
			wantErr: ErrCannotEncrypt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptAndEncodePayloadNonAEAD(tt.args.logger, tt.args.padded, tt.args.session, tt.args.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("encryptAndEncodePayloadNonAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				fmt.Println(hex.EncodeToString(got))
				t.Errorf("encryptAndEncodePayloadNonAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Regression test for MIV-01-003
func Test_Crash_EncryptAndEncodePayload(t *testing.T) {
	t.Run("improperly initialized dataCipher should panic", func(t *testing.T) {
		opt := &model.OpenVPNOptions{}
		st := &dataChannelState{
			hash:            sha1.New,
			cipherKeyLocal:  *(*keySlot)(bytes.Repeat([]byte{0x65}, 64)),
			cipherKeyRemote: *(*keySlot)(bytes.Repeat([]byte{0x66}, 64)),
			hmacKeyLocal:    *(*keySlot)(bytes.Repeat([]byte{0x67}, 64)),
			hmacKeyRemote:   *(*keySlot)(bytes.Repeat([]byte{0x68}, 64)),
		}
		dc := &DataChannel{
			options:        opt,
			sessionManager: makeTestingSession(),
			state:          st,
			decodeFn:       nil,
			encryptEncodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error) {
				return []byte{}, nil
			},
		}
		assertPanic(t, func() { dc.encryptAndEncodePayload(nil, dc.state) })
	})
}

type encryptEncodeFn func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error)

func Test_data_EncryptAndEncodePayload(t *testing.T) {
	type fields struct {
		options *model.OpenVPNOptions
		session *session.Manager
		state   *dataChannelState
	}
	type args struct {
		plaintext       []byte
		encryptEncodeFn encryptEncodeFn
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "dummy encryptEncodeFn does not fail",
			fields: fields{
				options: &model.OpenVPNOptions{Compress: model.CompressionEmpty},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
			},
			args: args{
				plaintext: []byte("hello"),
				encryptEncodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error) {
					return []byte{}, nil
				},
			},
			want:    []byte{},
			wantErr: nil,
		},
		{
			name: "empty plaintext fails",
			fields: fields{
				options: &model.OpenVPNOptions{Compress: model.CompressionEmpty},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
			},
			args: args{
				plaintext: []byte{},
				encryptEncodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error) {
					return []byte{}, nil
				},
			},
			want:    []byte{},
			wantErr: ErrCannotEncrypt,
		},
		{
			name: "error on encryptEncodeFn gets propagated",
			fields: fields{
				options: &model.OpenVPNOptions{Compress: model.CompressionEmpty},
				session: makeTestingSession(),
				state:   makeTestingStateAEAD(),
			},
			args: args{
				plaintext: []byte{},
				encryptEncodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error) {
					return []byte{}, errors.New("dummyTestError")
				},
			},
			want:    []byte{},
			wantErr: ErrCannotEncrypt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := &DataChannel{
				options:         tt.fields.options,
				sessionManager:  tt.fields.session,
				state:           tt.fields.state,
				encryptEncodeFn: tt.args.encryptEncodeFn,
			}
			got, err := dc.encryptAndEncodePayload(tt.args.plaintext, tt.fields.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.EncryptAndEncodePayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func Test_doCompress(t *testing.T) {
	type args struct {
		b   []byte
		opt model.Compression
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name:    "null compression should not fail",
			args:    args{},
			want:    []byte{},
			wantErr: nil,
		},
		{
			name: "do nothing by default",
			args: args{
				b:   []byte{0xde, 0xad, 0xbe, 0xef},
				opt: "",
			},
			want:    []byte{0xde, 0xad, 0xbe, 0xef},
			wantErr: nil,
		},
		{
			name: "stub appends the first byte at the end",
			args: args{
				b:   []byte{0xde, 0xad, 0xbe, 0xef},
				opt: "stub",
			},
			want:    []byte{0xfb, 0xad, 0xbe, 0xef, 0xde},
			wantErr: nil,
		},
		{
			name: "lzo-no adds 0xfa preamble",
			args: args{
				b:   []byte{0xde, 0xad, 0xbe, 0xef},
				opt: "lzo-no",
			},
			want:    []byte{0xfa, 0xde, 0xad, 0xbe, 0xef},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := doCompress(tt.args.b, tt.args.opt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("maybeAddCompressStub() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("maybeAddCompressStub() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_doPadding(t *testing.T) {
	type args struct {
		b         []byte
		compress  model.Compression
		blockSize uint8
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "add a whole padding block if len equal to block size, no padding stub",
			args: args{
				b:         []byte{0x00, 0x01, 0x02, 0x03},
				compress:  model.Compression(""),
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04},
			wantErr: nil,
		},
		{
			name: "compression stub with len == blocksize",
			args: args{
				b:         []byte{0x00, 0x01, 0x02, 0x03},
				compress:  model.CompressionStub,
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03},
			wantErr: nil,
		},
		{
			name: "compression stub with len < blocksize",
			args: args{
				b:         []byte{0x00, 0x01, 0xff},
				compress:  model.CompressionStub,
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0xff},
			wantErr: nil,
		},
		{
			name: "compression stub with len = blocksize + 1",
			args: args{
				b:         []byte{0x00, 0x01, 0x02, 0x03, 0xff},
				compress:  model.CompressionStub,
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0xff},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := doPadding(tt.args.b, tt.args.compress, tt.args.blockSize)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("doPadding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("doPadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_prependPacketID(t *testing.T) {
	type args struct {
		p   model.PacketID
		buf []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "append a single-byte packet id",
			args: args{
				model.PacketID(0x01),
				[]byte{0x07, 0x08},
			},
			want: []byte{0x00, 0x00, 0x00, 0x01, 0x07, 0x08},
		},
		{
			name: "append a four-byte packet id",
			args: args{
				model.PacketID(4294967295),
				[]byte{0x07, 0x08, 0x9, 0x10},
			},
			want: []byte{0xff, 0xff, 0xff, 0xff, 0x07, 0x08, 0x09, 0x10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := prependPacketID(tt.args.p, tt.args.buf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("prependPacketID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_maybeDecompress(t *testing.T) {

	getStateForDecompressTestNonAEAD := func() *dataChannelState {
		st := makeTestingStateNonAEAD()
		st.remotePacketID = model.PacketID(0x42)
		return st
	}

	type args struct {
		b   []byte
		st  *dataChannelState
		opt *model.OpenVPNOptions
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "nil state should fail",
			args: args{
				b:   []byte{},
				st:  nil,
				opt: &model.OpenVPNOptions{},
			},
			want:    []byte{},
			wantErr: ErrBadInput,
		},
		{
			name: "nil options should fail",
			args: args{
				b:   []byte{},
				st:  makeTestingStateAEAD(),
				opt: nil,
			},
			want:    []byte{},
			wantErr: ErrBadInput,
		},
		{
			name: "aead cipher, no compression",
			args: args{
				b:   []byte{0xaa, 0xbb, 0xcc},
				st:  makeTestingStateAEAD(),
				opt: &model.OpenVPNOptions{},
			},
			want:    []byte{0xaa, 0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, no compr",
			args: args{
				b:   []byte{0xfa, 0xbb, 0xcc},
				st:  makeTestingStateAEAD(),
				opt: &model.OpenVPNOptions{Compress: "stub"},
			},
			want:    []byte{0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, stub on options and stub on header",
			args: args{
				b:   []byte{0xfb, 0xbb, 0xcc, 0xdd},
				st:  makeTestingStateAEAD(),
				opt: &model.OpenVPNOptions{Compress: "stub"},
			},
			want:    []byte{0xdd, 0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, stub, unsupported compression",
			args: args{
				b:   []byte{0xff, 0xbb, 0xcc},
				st:  makeTestingStateAEAD(),
				opt: &model.OpenVPNOptions{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: errBadCompression,
		},
		{
			name: "aead cipher, lzo-no",
			args: args{
				b:   []byte{0xfa, 0xbb, 0xcc},
				st:  makeTestingStateAEAD(),
				opt: &model.OpenVPNOptions{Compress: "lzo-no"},
			},
			want:    []byte{0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, compress-no",
			args: args{
				b:   []byte{0x00, 0xbb, 0xcc},
				st:  makeTestingStateAEAD(),
				opt: &model.OpenVPNOptions{Compress: "no"},
			},
			want:    []byte{0x00, 0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "non-aead cipher, stub",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x43, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &model.OpenVPNOptions{Compress: "stub"},
			},
			want:    []byte{0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "non-aead cipher, stub, unsupported compression byte should fail",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x43, 0x0ff, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &model.OpenVPNOptions{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: errBadCompression,
		},
		{
			name: "non-aead cipher, compress-no should not fail",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x43, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &model.OpenVPNOptions{Compress: "no"},
			},
			want:    []byte{0x00, 0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "non-aead cipher, replay detected (equal remote packetID)",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x42, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &model.OpenVPNOptions{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: ErrReplayAttack,
		},
		{
			name: "non-aead cipher, replay detected (lesser remote packetID)",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x42, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &model.OpenVPNOptions{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: ErrReplayAttack,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := maybeDecompress(tt.args.b, tt.args.st, tt.args.opt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("maybeDecompress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maybeDecompress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func assertPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected code to panic")
		}
	}()
	f()
}
