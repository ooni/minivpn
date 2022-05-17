package vpn

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"reflect"
	"testing"
)

const (
	rnd32 = "01234567890123456789012345678901"
	rnd48 = "012345678901234567890123456789012345678901234567"
)

func getTestKeyMaterial() ([32]byte, [32]byte, [48]byte) {
	r1 := *(*[32]byte)([]byte(rnd32))
	r2 := *(*[32]byte)([]byte(rnd32))
	r3 := *(*[48]byte)([]byte(rnd48))
	return r1, r2, r3
}

// getDeterministicRandomKeySize returns a sequence of integer in a deterministic sequence
// using the map in the closure. we use this to construct a deterministic
// random function to replace the random function used in the real client.
func getDeterministicRandomKeySize() func() int {
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

	kgen := getDeterministicRandomKeySize()
	randomFn = func(int) ([]byte, error) {
		switch kgen() {
		case 32:
			return []byte(rnd32), nil
		case 48:
			return []byte(rnd48), nil
		default:
			return []byte(rnd32), nil
		}
	}

	r1, r2, premaster := getTestKeyMaterial()

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

func testingSession() *session {
	s := &session{
		RemoteSessionID: sessionID{0x01},
		LocalSessionID:  sessionID{0x02}}
	return s
}

func testingOptions(cipher, auth string) *Options {
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
				s:   testingSession(),
			},
			want:    nil,
			wantErr: errBadInput,
		},
		{
			name: "bad auth in Options should fail",
			args: args{
				opt: testingOptions("AES-128-GCM", "shabad"),
				s:   testingSession(),
			},
			wantWhatever: true,
			wantErr:      errBadInput,
		},
		{
			name: "empty session should not fail",
			args: args{
				opt: testingOptions("AES-128-GCM", "sha512"),
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

// TODO pass something useful
func testingDataChannelKey() *dataChannelKey {
	return &dataChannelKey{}
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
				session: testingSession(),
				state:   testingDataChannelState(),
			},
			args:    args{},
			wantErr: errBadInput,
		},
		{
			name: "dataChannelKey not ready",
			fields: fields{
				session: testingSession(),
				state:   testingDataChannelState(),
			},
			args: args{
				dck: &dataChannelKey{},
			},
			wantErr: errDataChannelKey,
		},
		{
			name: "good setup",
			fields: fields{
				session: testingSession(),
				state:   testingDataChannelState(),
			},
			args: args{
				dck: &dataChannelKey{},
			},
			wantErr: errDataChannelKey,
		},

		// TODO: Add test cases.
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
	r1, r2, premaster := getTestKeyMaterial()
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
		/*

			these tests are obsolete, delete
				{
					"single byte",
					fields{
						[]byte{0xff},
						[]byte{0xfe},
						[]byte{0xfd}},
					[]byte{0xfd, 0xff, 0xfe},
				},
				{
					"two byte",
					fields{[]byte{0xff, 0xfa}, []byte{0xfe, 0xea}, []byte{0xfd, 0xda}},
					[]byte{0xfd, 0xda, 0xff, 0xfa, 0xfe, 0xea},
				},
				{
					"empty bytes",
					fields{[]byte{}, []byte{}, []byte{}},
					[]byte(""),
				},
		*/
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
func testingDataChannelState() *dataChannelState {
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

func Test_decodeEncryptedPayloadAEAD(t *testing.T) {

	state := testingDataChannelState()

	key := state.cipherKeyRemote[:]
	log.Println("KEY", key, len(key))

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
			args{bytes.Repeat([]byte{0xff}, 27), &dataChannelState{}},
			&encryptedData{},
			true,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEncryptedPayloadNonAEAD(tt.args.buf, tt.args.state)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeEncryptedPayloadNonAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeEncryptedPayloadNonAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encryptAndEncodePayloadAEAD(t *testing.T) {

	options := &Options{Cipher: "AES-128-GCM"}
	state := testingDataChannelState()
	padded, _ := maybeAddCompressPadding([]byte("hello go tests"), options, state.dataCipher.blockSize())

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

			// DEBUG --------------------------------
			decoded, _ := decodeEncryptedPayloadAEAD(got, state)
			log.Println("decoded")
			log.Println(decoded.iv)
			log.Println(hex.EncodeToString(decoded.iv))
			log.Println(decoded)
			log.Println(decoded.ciphertext)
			log.Println(hex.EncodeToString(decoded.ciphertext))
			// DEBUG --------------------------------

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
		/*
			{
				"good encrypt",
				args{padded, &session{}, state},
				[]byte{},
				false,
			},
		*/
		// TODO: Add test cases.
		// TODO test passing bad nonce length to encrypt (panics)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptAndEncodePayloadNonAEAD(tt.args.padded, tt.args.session, tt.args.state)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptAndEncodePayloadNonAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encryptAndEncodePayloadNonAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}
