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
	rnd16 = "0123456789012345"
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

func testingDataChannelKey() *dataChannelKey {
	rl1, rl2, preml := getTestKeyMaterial()
	rr1, rr2, premr := getTestKeyMaterial()

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
				dck: testingDataChannelKey(),
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

func testingDataChannelStateNonAEAD() *dataChannelState {
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

	padded16 := bytes.Repeat([]byte{0xff}, 16)
	padded15 := bytes.Repeat([]byte{0xff}, 15)

	goodEncrypted, _ := hex.DecodeString("fdf9b069b2e5a637fa7b5c9231166ea96307e4123031323334353637383930313233343581e4878c5eec602c2d2f5a95139c84af")
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
				state:   testingDataChannelStateNonAEAD()},
			want:    goodEncrypted,
			wantErr: nil,
		},
		{
			name: "badly padded input should fail",
			args: args{
				padded:  padded15,
				session: &session{},
				state:   testingDataChannelStateNonAEAD()},
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
		opt       *Options
		blockSize int
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
				opt:       &Options{},
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04},
			wantErr: nil,
		},
		{
			name: "compression stub with len == blocksize",
			args: args{
				b:         []byte{0x00, 0x01, 0x02, 0x03},
				opt:       &Options{Compress: compressionStub},
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03},
			wantErr: nil,
		},
		{
			name: "compression stub with len < blocksize",
			args: args{
				b:         []byte{0x00, 0x01, 0xff},
				opt:       &Options{Compress: compressionStub},
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0xff},
			wantErr: nil,
		},
		{
			name: "compression stub with len = blocksize + 1",
			args: args{
				b:         []byte{0x00, 0x01, 0x02, 0x03, 0xff},
				opt:       &Options{Compress: compressionStub},
				blockSize: 4,
			},
			want:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0xff},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := maybeAddCompressPadding(tt.args.b, tt.args.opt, tt.args.blockSize)
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
