package vpn

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"reflect"
	"testing"

	"github.com/ainghazal/minivpn/vpn/mocks"
)

const (
	rnd16 = "0123456789012345"
	rnd32 = "01234567890123456789012345678901"
	rnd48 = "012345678901234567890123456789012345678901234567"
)

func makeTestKeys() ([32]byte, [32]byte, [48]byte) {
	r1 := *(*[32]byte)([]byte(rnd32))
	r2 := *(*[32]byte)([]byte(rnd32))
	r3 := *(*[48]byte)([]byte(rnd48))
	return r1, r2, r3
}

// getDeterministicRandomKeySize returns a sequence of integers
// using the map in the closure. we use this to construct a deterministic
// random function to replace the random function used in the real client.
func getDeterministicRandomKeySizeFn() func() int {
	var rndSeq = map[int]int{
		1: 32,
		2: 32,
		3: 48,
	}
	i := 1
	f := func() int {
		v := rndSeq[i]
		i += 1
		return v
	}
	return f
}

func Test_newKeySource(t *testing.T) {

	genKeySizeFn := getDeterministicRandomKeySizeFn()

	// we replace the global random function used in the constructor
	randomFn = func(int) ([]byte, error) {
		switch genKeySizeFn() {
		case 48:
			return []byte(rnd48), nil
		default:
			return []byte(rnd32), nil
		}
	}

	r1, r2, premaster := makeTestKeys()
	ks := &keySource{r1, r2, premaster}

	tests := []struct {
		name string
		want *keySource
	}{
		{
			name: "test generation of a new key with mocked random data",
			want: ks,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := newKeySource(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newKeySource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func makeTestingSession() *session {
	s := &session{
		RemoteSessionID: sessionID{0x01},
		LocalSessionID:  sessionID{0x02}}
	return s
}

func makeTestingOptions(cipher, auth string) *Options {
	opt := &Options{
		Cipher: cipher,
		Auth:   auth,
	}
	return opt
}

func Test_newDataFromOptions(t *testing.T) {
	type args struct {
		opt *Options
		s   *session
	}
	tests := []struct {
		name         string
		args         args
		want         *data
		wantWhatever bool
		wantErr      error
	}{
		{
			name:    "nil args should fail",
			args:    args{},
			want:    nil,
			wantErr: errBadInput,
		},
		{
			name: "empty Options should fail",
			args: args{
				opt: &Options{},
				s:   makeTestingSession(),
			},
			want:    nil,
			wantErr: errBadInput,
		},
		{
			name: "bad auth in Options should fail",
			args: args{
				opt: makeTestingOptions("AES-128-GCM", "shabad"),
				s:   makeTestingSession(),
			},
			wantWhatever: true,
			wantErr:      errBadInput,
		},
		{
			name: "empty session should not fail",
			args: args{
				opt: makeTestingOptions("AES-128-GCM", "sha512"),
				s:   &session{},
			},
			wantWhatever: true,
			wantErr:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newDataFromOptions(tt.args.opt, tt.args.s)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("newDataFromOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantWhatever && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newDataFromOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func makeTestingDataChannelKey() *dataChannelKey {
	rl1, rl2, preml := makeTestKeys()
	rr1, rr2, premr := makeTestKeys()

	ksLocal := &keySource{rl1, rl2, preml}
	ksRemote := &keySource{rr1, rr2, premr}

	dck := &dataChannelKey{
		ready:  true,
		local:  ksLocal,
		remote: ksRemote,
	}
	return dck
}

func Test_data_SetupKeys(t *testing.T) {
	type fields struct {
		session *session
		state   *dataChannelState
	}
	type args struct {
		dck *dataChannelKey
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "nil in arguments should fail",
			fields: fields{
				session: makeTestingSession(),
				state:   makeTestingState(),
			},
			args:    args{},
			wantErr: errBadInput,
		},
		{
			name: "dataChannelKey not ready",
			fields: fields{
				session: makeTestingSession(),
				state:   makeTestingState(),
			},
			args: args{
				dck: &dataChannelKey{},
			},
			wantErr: errDataChannelKey,
		},
		{
			name: "good setup",
			fields: fields{
				session: makeTestingSession(),
				state:   makeTestingState(),
			},
			args: args{
				dck: makeTestingDataChannelKey(),
			},
			wantErr: nil,
			// TODO(ainghazal): should write another test to verify the key derivation?
			// but what that would be testing, if not the implementation?
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &data{
				session: tt.fields.session,
				state:   tt.fields.state,
			}
			if err := d.SetupKeys(tt.args.dck); !errors.Is(err, tt.wantErr) {
				t.Errorf("data.SetupKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_data_EncryptAndEncodePayload(t *testing.T) {

	opt := &Options{}

	type fields struct {
		options         *Options
		session         *session
		state           *dataChannelState
		decodeFn        func([]byte, *dataChannelState) (*encryptedData, error)
		encryptEncodeFn func([]byte, *session, *dataChannelState) ([]byte, error)
	}
	type args struct {
		plaintext []byte
		dcs       *dataChannelState
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
				options:  opt,
				session:  makeTestingSession(),
				state:    makeTestingState(),
				decodeFn: nil,
				encryptEncodeFn: func(b []byte, s *session, st *dataChannelState) ([]byte, error) {
					return []byte{}, nil
				},
			},
			args: args{
				plaintext: []byte("hello"),
				dcs:       makeTestingState(),
			},
			want:    []byte{},
			wantErr: nil,
		},
		{
			name: "empty plaintext does not fail",
			fields: fields{
				options:  opt,
				session:  makeTestingSession(),
				state:    makeTestingState(),
				decodeFn: nil,
				encryptEncodeFn: func(b []byte, s *session, st *dataChannelState) ([]byte, error) {
					return []byte{}, nil
				},
			},
			args: args{
				plaintext: []byte{},
				dcs:       makeTestingState(),
			},
			want:    []byte{},
			wantErr: nil,
		},
		{
			name: "error on encryptEncodeFn gets propagated",
			fields: fields{
				options:  opt,
				session:  makeTestingSession(),
				state:    makeTestingState(),
				decodeFn: nil,
				encryptEncodeFn: func(b []byte, s *session, st *dataChannelState) ([]byte, error) {
					return []byte{}, errors.New("dummyTestError")
				},
			},
			args: args{
				plaintext: []byte{},
				dcs:       makeTestingState(),
			},
			want:    []byte{},
			wantErr: errCannotEncrypt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &data{
				options:         tt.fields.options,
				session:         tt.fields.session,
				state:           tt.fields.state,
				decodeFn:        tt.fields.decodeFn,
				encryptEncodeFn: tt.fields.encryptEncodeFn,
			}
			got, err := d.EncryptAndEncodePayload(tt.args.plaintext, tt.args.dcs)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.EncryptAndEncodePayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("data.EncryptAndEncodePayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dataChannelState_RemotePacketID(t *testing.T) {
	type fields struct {
		remotePacketID packetID
	}
	tests := []struct {
		name    string
		fields  fields
		want    packetID
		wantErr error
	}{
		{
			"zero",
			fields{0},
			packetID(0),
			nil,
		},
		{
			"one",
			fields{1},
			packetID(1),
			nil,
		},
		{
			"overflow",
			fields{math.MaxUint32},
			packetID(0),
			errExpiredKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcs := &dataChannelState{
				remotePacketID: tt.fields.remotePacketID,
			}
			if got, err := dcs.RemotePacketID(); got != tt.want || err != tt.wantErr {
				t.Errorf("dataChannelState.RemotePacketID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_keySource_Bytes(t *testing.T) {
	r1, r2, premaster := makeTestKeys()
	goodSerialized := append(premaster[:], r1[:]...)
	goodSerialized = append(goodSerialized, r2[:]...)

	type fields struct {
		r1        [32]byte
		r2        [32]byte
		preMaster [48]byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "good keysource",
			fields: fields{
				r1:        r1,
				r2:        r2,
				preMaster: premaster,
			},
			want: goodSerialized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &keySource{
				r1:        tt.fields.r1,
				r2:        tt.fields.r2,
				preMaster: tt.fields.preMaster,
			}
			if got := k.Bytes(); !bytes.Equal(got, tt.want) {
				t.Errorf("keySource.Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dataChannelKey_addRemoteKey(t *testing.T) {
	type fields struct {
		ready  bool
		remote *keySource
	}
	type args struct {
		k *keySource
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"passing a keysource should make it ready",
			fields{false, &keySource{}},
			args{&keySource{}},
			false,
		},
		{
			"fail if ready",
			fields{true, &keySource{}},
			args{&keySource{}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dck := &dataChannelKey{
				ready:  tt.fields.ready,
				remote: tt.fields.remote,
			}
			if err := dck.addRemoteKey(tt.args.k); (err != nil) != tt.wantErr {
				t.Errorf("dataChannelKey.addRemoteKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func makeTestingState() *dataChannelState {
	dataCipher, _ := newDataCipher(cipherNameAES, 128, cipherModeGCM)
	st := &dataChannelState{
		hmacSize: 20,
		hmac:     sha1.New,
		// my linter doesn't like it, but this is the proper way of casting to keySlot
		cipherKeyLocal:  *(*keySlot)(bytes.Repeat([]byte{0x65}, 64)),
		cipherKeyRemote: *(*keySlot)(bytes.Repeat([]byte{0x66}, 64)),
		hmacKeyLocal:    *(*keySlot)(bytes.Repeat([]byte{0x67}, 64)),
		hmacKeyRemote:   *(*keySlot)(bytes.Repeat([]byte{0x68}, 64)),
	}
	st.dataCipher = dataCipher
	return st
}

func makeTestingStateNonAEAD() *dataChannelState {
	dataCipher, _ := newDataCipher(cipherNameAES, 128, cipherModeCBC)
	st := &dataChannelState{
		hmacSize: 20,
		hmac:     sha1.New,
		// my linter doesn't like it, but this is the proper way of casting to keySlot
		cipherKeyLocal:  *(*keySlot)(bytes.Repeat([]byte{0x65}, 64)),
		cipherKeyRemote: *(*keySlot)(bytes.Repeat([]byte{0x66}, 64)),
		hmacKeyLocal:    *(*keySlot)(bytes.Repeat([]byte{0x67}, 64)),
		hmacKeyRemote:   *(*keySlot)(bytes.Repeat([]byte{0x68}, 64)),
	}
	st.dataCipher = dataCipher
	return st
}

func makeTestingStateNonAEADReversed() *dataChannelState {
	dataCipher, _ := newDataCipher(cipherNameAES, 128, cipherModeCBC)
	st := &dataChannelState{
		hmacSize: 20,
		hmac:     sha1.New,
		// my linter doesn't like it, but this is the proper way of casting to keySlot
		cipherKeyRemote: *(*keySlot)(bytes.Repeat([]byte{0x65}, 64)),
		cipherKeyLocal:  *(*keySlot)(bytes.Repeat([]byte{0x66}, 64)),
		hmacKeyRemote:   *(*keySlot)(bytes.Repeat([]byte{0x67}, 64)),
		hmacKeyLocal:    *(*keySlot)(bytes.Repeat([]byte{0x68}, 64)),
	}
	st.dataCipher = dataCipher
	return st
}

func Test_data_decrypt(t *testing.T) {

	goodMockDecryptFn := func([]byte, *encryptedData) ([]byte, error) {
		return []byte("alles ist gut"), nil
	}

	failingMockDecryptFn := func([]byte, *encryptedData) ([]byte, error) {
		return []byte{}, errCannotDecrypt
	}

	opt := &Options{}

	type fields struct {
		options         *Options
		session         *session
		state           *dataChannelState
		decodeFn        func([]byte, *dataChannelState) (*encryptedData, error)
		encryptEncodeFn func([]byte, *session, *dataChannelState) ([]byte, error)
		decryptFn       func([]byte, *encryptedData) ([]byte, error)
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
			name: "empty output in decodeFn does fail",
			fields: fields{
				options: opt,
				session: makeTestingSession(),
				state:   makeTestingState(),
				decodeFn: func(b []byte, st *dataChannelState) (*encryptedData, error) {
					return &encryptedData{}, nil
				},
				encryptEncodeFn: nil,
				decryptFn:       makeTestingState().dataCipher.decrypt,
			},
			args: args{
				encrypted: bytes.Repeat([]byte{0x0a}, 20),
			},
			want:    []byte{},
			wantErr: errCannotDecrypt,
		},
		{
			name: "empty encrypted input does fail",
			fields: fields{
				options: opt,
				session: makeTestingSession(),
				state:   makeTestingState(),
				decodeFn: func(b []byte, st *dataChannelState) (*encryptedData, error) {
					return &encryptedData{}, nil
				},
				encryptEncodeFn: nil,
				decryptFn:       makeTestingState().dataCipher.decrypt,
			},
			args: args{
				encrypted: []byte{},
			},
			want:    []byte{},
			wantErr: errCannotDecrypt,
		},
		{
			name: "error in decrypt propagates",
			fields: fields{
				options: opt,
				session: makeTestingSession(),
				state:   makeTestingState(),
				decodeFn: func(b []byte, st *dataChannelState) (*encryptedData, error) {
					return &encryptedData{}, nil
				},
				encryptEncodeFn: nil,
				decryptFn:       failingMockDecryptFn,
			},
			args: args{
				encrypted: []byte{},
			},
			want:    []byte{},
			wantErr: errCannotDecrypt,
		},
		{
			name: "good decrypt returns expected output",
			fields: fields{
				options: opt,
				session: makeTestingSession(),
				state:   makeTestingState(),
				decodeFn: func(b []byte, st *dataChannelState) (*encryptedData, error) {
					return &encryptedData{}, nil
				},
				encryptEncodeFn: nil,
				decryptFn:       goodMockDecryptFn,
			},
			args: args{
				encrypted: []byte{},
			},
			want:    []byte("alles ist gut"),
			wantErr: nil,
		},
		// TODO we already are testing decrypt + encrypt in the crypto module
		// so we can mock the decrypt here in the state.
		// TODO empty ciphertext raises error
		// TODO: Add moar test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &data{
				options:         tt.fields.options,
				session:         tt.fields.session,
				state:           tt.fields.state,
				decodeFn:        tt.fields.decodeFn,
				encryptEncodeFn: tt.fields.encryptEncodeFn,
				decryptFn:       tt.fields.decryptFn,
			}
			got, err := d.decrypt(tt.args.encrypted)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("data.decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeEncryptedPayloadAEAD(t *testing.T) {

	state := makeTestingState()

	goodEncryptedPayload, _ := hex.DecodeString("00000000b3653a842f2b8a148de26375218fb01d31278ff328ff2fc65c4dbf9eb8e67766")
	goodDecodeIV, _ := hex.DecodeString("000000006868686868686868")
	goodDecodeCipherText, _ := hex.DecodeString("31278ff328ff2fc65c4dbf9eb8e67766b3653a842f2b8a148de26375218fb01d")
	goodDecodeAEAD, _ := hex.DecodeString("00000000")

	type args struct {
		buf   []byte
		state *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    *encryptedData
		wantErr bool
	}{
		{
			"empty",
			args{[]byte{}, &dataChannelState{}},
			&encryptedData{},
			true,
		},
		{
			"too short",
			args{bytes.Repeat([]byte{0xff}, 19), &dataChannelState{}},
			&encryptedData{},
			true,
		},
		{
			"good decode",
			args{goodEncryptedPayload, state},
			&encryptedData{
				iv:         goodDecodeIV,
				ciphertext: goodDecodeCipherText,
				aead:       goodDecodeAEAD,
			},
			false,
		},
		// TODO: Add moar test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEncryptedPayloadAEAD(tt.args.buf, tt.args.state)
			if (err != nil) != tt.wantErr {
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
		buf   []byte
		state *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    *encryptedData
		wantErr error
	}{
		{
			name:    "empty",
			args:    args{[]byte{}, &dataChannelState{}},
			want:    &encryptedData{},
			wantErr: errBadInput,
		},
		{
			name:    "too short",
			args:    args{bytes.Repeat([]byte{0xff}, 27), &dataChannelState{}},
			want:    &encryptedData{},
			wantErr: errBadInput,
		},
		{
			name:    "nil state should fail",
			args:    args{goodInput, nil},
			want:    &encryptedData{},
			wantErr: errBadInput,
		},
		{
			name:    "empty state.dataCipher should fail",
			args:    args{goodInput, &dataChannelState{}},
			want:    &encryptedData{},
			wantErr: errBadInput,
		},
		{
			name: "good decode",
			args: args{goodInput, makeTestingStateNonAEADReversed()},
			want: &encryptedData{
				iv:         iv,
				ciphertext: ciphertext,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEncryptedPayloadNonAEAD(tt.args.buf, tt.args.state)
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

func Test_encryptAndEncodePayloadAEAD(t *testing.T) {

	state := makeTestingState()
	padded, _ := maybeAddCompressPadding([]byte("hello go tests"), "", state.dataCipher.blockSize())

	goodEncryptedPayload, _ := hex.DecodeString("00000000b3653a842f2b8a148de26375218fb01d31278ff328ff2fc65c4dbf9eb8e67766")

	type args struct {
		padded  []byte
		session *session
		state   *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"good encrypt",
			args{padded, &session{}, state},
			goodEncryptedPayload,
			false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptAndEncodePayloadAEAD(tt.args.padded, tt.args.session, tt.args.state)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptAndEncodePayloadAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encryptAndEncodePayloadAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encryptAndEncodePayloadNonAEAD(t *testing.T) {

	padded16 := bytes.Repeat([]byte{0xff}, 16)
	padded15 := bytes.Repeat([]byte{0xff}, 15)

	goodEncrypted, _ := hex.DecodeString("fdf9b069b2e5a637fa7b5c9231166ea96307e4123031323334353637383930313233343581e4878c5eec602c2d2f5a95139c84af")

	// we replace the global random function that is used for the iv in, e.g., CBC mode.
	randomFn = func(i int) ([]byte, error) {
		switch i {
		case 16:
			return []byte(rnd16), nil
		default:
			return []byte(rnd32), nil
		}
	}

	type args struct {
		padded  []byte
		session *session
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
				padded:  padded16,
				session: &session{},
				state:   makeTestingStateNonAEAD()},
			want:    goodEncrypted,
			wantErr: nil,
		},
		{
			name: "badly padded input should fail",
			args: args{
				padded:  padded15,
				session: &session{},
				state:   makeTestingStateNonAEAD()},
			want:    nil,
			wantErr: errCannotEncrypt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptAndEncodePayloadNonAEAD(tt.args.padded, tt.args.session, tt.args.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("encryptAndEncodePayloadNonAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("encryptAndEncodePayloadNonAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_maybeAddCompressStub(t *testing.T) {
	type args struct {
		b   []byte
		opt *Options
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name:    "nil opts should fail",
			args:    args{},
			want:    nil,
			wantErr: errBadInput,
		},
		{
			name: "do nothing by default",
			args: args{
				b:   []byte{0xde, 0xad, 0xbe, 0xef},
				opt: &Options{},
			},
			want:    []byte{0xde, 0xad, 0xbe, 0xef},
			wantErr: nil,
		},
		{
			name: "stub appends the first byte at the end",
			args: args{
				b: []byte{0xde, 0xad, 0xbe, 0xef},
				opt: &Options{
					Compress: "stub",
				},
			},
			want:    []byte{0xfb, 0xad, 0xbe, 0xef, 0xde},
			wantErr: nil,
		},
		{
			name: "lzo-no adds 0xfa preamble",
			args: args{
				b: []byte{0xde, 0xad, 0xbe, 0xef},
				opt: &Options{
					Compress: "lzo-no",
				},
			},
			want:    []byte{0xfa, 0xde, 0xad, 0xbe, 0xef},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := maybeAddCompressStub(tt.args.b, tt.args.opt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("maybeAddCompressStub() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maybeAddCompressStub() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_maybeAddCompressPadding(t *testing.T) {
	type args struct {
		b         []byte
		compress  compression
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
				compress:  compression(""),
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04},
			wantErr: nil,
		},
		{
			name: "compression stub with len == blocksize",
			args: args{
				b:         []byte{0x00, 0x01, 0x02, 0x03},
				compress:  compressionStub,
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03},
			wantErr: nil,
		},
		{
			name: "compression stub with len < blocksize",
			args: args{
				b:         []byte{0x00, 0x01, 0xff},
				compress:  compressionStub,
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0xff},
			wantErr: nil,
		},
		{
			name: "compression stub with len = blocksize + 1",
			args: args{
				b:         []byte{0x00, 0x01, 0x02, 0x03, 0xff},
				compress:  compressionStub,
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0xff},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := maybeAddCompressPadding(tt.args.b, tt.args.compress, tt.args.blockSize)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("maybeAddCompressPadding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maybeAddCompressPadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_maybeDecompress(t *testing.T) {

	getStateForDecompressTestNonAEAD := func() *dataChannelState {
		st := makeTestingStateNonAEAD()
		st.remotePacketID = packetID(0x42)
		return st
	}

	type args struct {
		b   []byte
		st  *dataChannelState
		opt *Options
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
				opt: &Options{},
			},
			want:    []byte{},
			wantErr: errBadInput,
		},
		{
			name: "nil options should fail",
			args: args{
				b:   []byte{},
				st:  makeTestingState(),
				opt: nil,
			},
			want:    []byte{},
			wantErr: errBadInput,
		},
		{
			name: "aead cipher, no compression",
			args: args{
				b:   []byte{0xaa, 0xbb, 0xcc},
				st:  makeTestingState(),
				opt: &Options{},
			},
			want:    []byte{0xaa, 0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, no compr",
			args: args{
				b:   []byte{0xfa, 0xbb, 0xcc},
				st:  makeTestingState(),
				opt: &Options{Compress: "stub"},
			},
			want:    []byte{0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, stub on options and stub on header",
			args: args{
				b:   []byte{0xfb, 0xbb, 0xcc, 0xdd},
				st:  makeTestingState(),
				opt: &Options{Compress: "stub"},
			},
			want:    []byte{0xdd, 0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, stub, unsupported compression",
			args: args{
				b:   []byte{0xff, 0xbb, 0xcc},
				st:  makeTestingState(),
				opt: &Options{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: errBadCompression,
		},
		{
			name: "aead cipher, lzo-no",
			args: args{
				b:   []byte{0xfa, 0xbb, 0xcc},
				st:  makeTestingState(),
				opt: &Options{Compress: "lzo-no"},
			},
			want:    []byte{0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "aead cipher, compress-no",
			args: args{
				b:   []byte{0x00, 0xbb, 0xcc},
				st:  makeTestingState(),
				opt: &Options{Compress: "no"},
			},
			want:    []byte{0x00, 0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "non-aead cipher, stub",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x43, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &Options{Compress: "stub"},
			},
			want:    []byte{0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "non-aead cipher, stub, unsupported compression",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x43, 0x0ff, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &Options{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: errBadCompression,
		},
		{
			name: "non-aead cipher, compress-no",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x43, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &Options{Compress: "no"},
			},
			want:    []byte{0xbb, 0xcc},
			wantErr: nil,
		},
		{
			name: "non-aead cipher, replay detected (equal remote packetID)",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x42, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &Options{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: errReplayAttack,
		},
		{
			name: "non-aead cipher, replay detected (lesser remote packetID)",
			args: args{
				b:   []byte{0x00, 0x00, 0x00, 0x42, 0x00, 0xbb, 0xcc},
				st:  getStateForDecompressTestNonAEAD(),
				opt: &Options{Compress: "stub"},
			},
			want:    []byte{},
			wantErr: errReplayAttack,
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

func Test_data_ReadPacket(t *testing.T) {

	goodMockDecodeFn := func([]byte, *dataChannelState) (*encryptedData, error) {
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
		options   *Options
		state     *dataChannelState
		decryptFn func([]byte, *encryptedData) ([]byte, error)
		decodeFn  func([]byte, *dataChannelState) (*encryptedData, error)
	}
	type args struct {
		p *packet
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
				options:   makeTestingOptions("AES-128-GCM", "sha1"),
				state:     makeTestingState(),
				decryptFn: goodMockDecryptFn,
				decodeFn:  goodMockDecodeFn,
			},
			args: args{&packet{
				opcode:  pDataV1,
				payload: []byte("garbled")},
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
			d := &data{
				options:   tt.fields.options,
				state:     tt.fields.state,
				decryptFn: tt.fields.decryptFn,
				decodeFn:  tt.fields.decodeFn,
				//session:         tt.fields.session,
			}
			got, err := d.ReadPacket(tt.args.p)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.ReadPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("data.ReadPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

// we'll use a mocked net.Conn for WritePacket

func makeTestingConnForWrite(network, addr string, n int) net.Conn {
	mockAddr := &mocks.Addr{}
	mockAddr.MockString = func() string {
		return addr
	}
	mockAddr.MockNetwork = func() string {
		return network
	}

	mockConn := &mocks.Conn{}
	mockConn.MockLocalAddr = func() net.Addr {
		return mockAddr
	}
	mockConn.MockWrite = func([]byte) (int, error) {
		return n, nil
	}
	return mockConn
}

func Test_data_WritePacket(t *testing.T) {
	opt := &Options{}

	goodMockEncodedEncryptFn := func([]byte, *session, *dataChannelState) ([]byte, error) {
		return []byte("alles ist garbled gut"), nil
	}

	type fields struct {
		options *Options
		// session is only used for NonAEAD encryption
		session         *session
		state           *dataChannelState
		encryptEncodeFn func([]byte, *session, *dataChannelState) ([]byte, error)
	}
	type args struct {
		conn    net.Conn
		payload []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    int
		wantErr error
	}{
		{
			name: "good write, aead encryption",
			fields: fields{
				options:         opt,
				session:         nil,
				state:           makeTestingState(),
				encryptEncodeFn: goodMockEncodedEncryptFn,
			},
			args: args{
				conn:    makeTestingConnForWrite("udp", "10.0.42.1", 42),
				payload: []byte("hello test"),
			},
			want:    42,
			wantErr: nil,
		},

		// TODO: Add moar test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &data{
				options:         tt.fields.options,
				session:         tt.fields.session,
				state:           tt.fields.state,
				encryptEncodeFn: tt.fields.encryptEncodeFn,
			}
			got, err := d.WritePacket(tt.args.conn, tt.args.payload)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("data.WritePacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("data.WritePacket() = %v, want %v", got, tt.want)
			}
		})
	}
}
