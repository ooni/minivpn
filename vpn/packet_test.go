package vpn

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func Test_newPacketFromPayload(t *testing.T) {
	type args struct {
		opcode  uint8
		keyID   uint8
		payload []byte
	}
	tests := []struct {
		name string
		args args
		want *packet
	}{
		{
			name: "get packet ok",
			args: args{
				opcode:  1,
				keyID:   10,
				payload: []byte("this is not a payload"),
			},
			want: &packet{
				opcode:  1,
				keyID:   10,
				payload: []byte("this is not a payload"),
			},
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newPacketFromPayload(tt.args.opcode, tt.args.keyID, tt.args.payload); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newPacketFromPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_packet_Bytes(t *testing.T) {
	got := (&packet{opcode: pACKV1}).Bytes()
	want := []byte{40, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("newPacketFromBytes() = %v, want %v", got, want)
	}

	id := packetID(1)
	tooManyAcks := []packetID{
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
	}

	p := &packet{
		opcode: pACKV1,
		acks:   tooManyAcks,
	}
	got = p.Bytes()
	if len(got) != 1038 {
		t.Errorf("packet.Bytes(): expected len = %v, got %v", 1038, len(got))
	}
}

func Test_packet_isControlV1(t *testing.T) {
	type fields struct {
		opcode byte
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "good control",
			fields: fields{opcode: pControlV1},
			want:   true,
		},
		{
			name:   "no control",
			fields: fields{opcode: pDataV1},
			want:   false,
		},
		{
			name:   "zero byte",
			fields: fields{opcode: 0x00},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &packet{
				opcode: tt.fields.opcode,
			}
			if got := p.isControlV1(); got != tt.want {
				t.Errorf("packet.isControlV1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newACKPacket(t *testing.T) {
	type args struct {
		ackID packetID
		s     *session
	}
	tests := []struct {
		name string
		args args
		want *packet
	}{
		{"good_ack",
			args{42, &session{}},
			&packet{opcode: pACKV1, acks: []packetID{42}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newACKPacket(tt.args.ackID, tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newACKPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_packet_isACK(t *testing.T) {
	type fields struct {
		opcode byte
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "ack is good",
			fields: fields{0x05},
			want:   true,
		},
		{
			name:   "not ack",
			fields: fields{0x01},
			want:   false,
		},
		{
			name:   "also not ack",
			fields: fields{0x06},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &packet{
				opcode: tt.fields.opcode,
			}
			if got := p.isACK(); got != tt.want {
				t.Errorf("packet.isACK() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isPing(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"good ping", args{pingPayload}, true},
		{"bad ping", args{append(pingPayload, 0x00)}, false},
		{"empty", args{[]byte{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPing(tt.args.b); got != tt.want {
				t.Errorf("isPing() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newServerControlMessageFromBytes(t *testing.T) {
	payload := []byte{0xff, 0xfe, 0xfd}
	m := newServerControlMessageFromBytes(payload)
	if !bytes.Equal(m.payload, payload) {
		t.Errorf("newServerControlMessageFromBytes() = got %v, want %v", m.payload, payload)
	}
}

func Test_serverControlMessage_valid(t *testing.T) {
	type fields struct {
		payload []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			"good control message",
			fields{controlMessageHeader},
			true,
		},
		{
			"bad control message",
			fields{[]byte{0x00, 0x00, 0x00, 0x01}},
			false,
		},
		{
			"empty control message",
			fields{[]byte{}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &serverControlMessage{
				payload: tt.fields.payload,
			}
			if got := sc.valid(); got != tt.want {
				t.Errorf("serverControlMessage.valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseServerControlMessage(t *testing.T) {
	serverRespHex := "0000000002a490a20a83086e255b4d6c2a10ee9c488d683d1a1337bd4b32b24196a49c98632f00fddcab2c261cb6efae333eed9e1a7f83f3095a0da79b7a6f4709fe1ae040008856342c6465762d747970652074756e2c6c696e6b2d6d747520313535312c74756e2d6d747520313530302c70726f746f2054435076345f5345525645522c636970686572204145532d3235362d47434d2c61757468205b6e756c6c2d6469676573745d2c6b657973697a65203235362c6b65792d6d6574686f6420322c746c732d73657276657200"
	wantOptions := "V4,dev-type tun,link-mtu 1551,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
	wantRandom1, _ := hex.DecodeString("a490a20a83086e255b4d6c2a10ee9c488d683d1a1337bd4b32b24196a49c9863")
	wantRandom2, _ := hex.DecodeString("2f00fddcab2c261cb6efae333eed9e1a7f83f3095a0da79b7a6f4709fe1ae040")

	payload, _ := hex.DecodeString(serverRespHex)

	m := newServerControlMessageFromBytes(payload)
	gotKeySource, gotOptions, _ := parseServerControlMessage(m)

	if wantOptions != gotOptions {
		t.Errorf("parseServerControlMessage(). got options = %v, want options %v", gotOptions, wantOptions)
	}
	if !bytes.Equal(wantRandom1, gotKeySource.r1[:]) {
		t.Errorf("parseServerControlMessage(). got ks.r1 = %v, want ks.r1 %v", gotKeySource.r1, wantRandom1)
	}
	if !bytes.Equal(wantRandom2, gotKeySource.r2[:]) {
		t.Errorf("parseServerControlMessage(). got ks.r2 = %v, want ks.r2 %v", gotKeySource.r2, wantRandom2)
	}
}

func Test_encodeClientControlMessageAsBytes(t *testing.T) {

	var manyA, manyB [32]byte
	var manyC [48]byte

	copy(manyA[:], bytes.Repeat([]byte{0x65}, 32))
	copy(manyB[:], bytes.Repeat([]byte{0x66}, 32))
	copy(manyC[:], bytes.Repeat([]byte{0x67}, 48))

	type args struct {
		k *keySource
		o *Options
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"empty options",
			args{
				&keySource{manyA, manyB, manyC},
				&Options{},
			},
			func() []byte {
				buf := []byte{0x00, 0x00, 0x00, 0x00, 0x02}
				buf = append(buf, manyC[:]...)
				buf = append(buf, manyA[:]...)
				buf = append(buf, manyB[:]...)
				buf = append(buf, []byte{
					// options, null-terminated
					0x00, 0x01, 0x00,
					// auth strings
					0x00, 0x01, 0x00,
					0x00, 0x01, 0x00}...)
				return buf
			}(),
			false,
		},
		{
			"good options",
			args{
				&keySource{manyA, manyB, manyC},
				&Options{Cipher: "AES-128-CBC"},
			},
			func() []byte {
				buf := []byte{0x00, 0x00, 0x00, 0x00, 0x02}
				buf = append(buf, manyC[:]...)
				buf = append(buf, manyA[:]...)
				buf = append(buf, manyB[:]...)
				buf = append(buf, []byte{0x00, 0x74}...)
				buf = append(buf, []byte("V1,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-128-CBC,auth ,keysize 128,key-method 2,tls-client")...)
				// null-terminate + auth
				buf = append(buf, []byte{
					0x00,
					0x00, 0x01, 0x00,
					0x00, 0x01, 0x00}...)
				return buf
			}(),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeClientControlMessageAsBytes(tt.args.k, tt.args.o)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeClientControlMessageAsBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeClientControlMessageAsBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parsePacketFromBytes(t *testing.T) {
	type args struct {
		buf []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *packet
		wantErr bool
	}{
		{
			"ack",
			args{[]byte{0x28, 0xff, 0xff}},
			&packet{
				opcode: pACKV1, keyID: 0,
				payload: []byte{0xff, 0xff}},
			false,
		},
		{
			"hard reset",
			args{[]byte{0x8, 0xff, 0xff}},
			&packet{
				opcode:  pControlHardResetClientV1,
				keyID:   0,
				payload: []byte{0xff, 0xff}},
			false,
		},
		{
			"hard reset server",
			args{[]byte{0x10, 0xff, 0xff}},
			&packet{
				opcode:  pControlHardResetServerV1,
				keyID:   0,
				payload: []byte{0xff, 0xff},
			},
			false},
		{
			"empty payload",
			args{[]byte{0x28}},
			&packet{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePacketFromBytes(tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("newPacketFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newPacketFromBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseControlPacket(t *testing.T) {
	raw1 := "5ad4a9517af8e7fe000000000296f517f943d32a11fc8463b8594ae7d3523b627d8c9444aac2def81a13bea2e037aecbd158bdf50ed16e800829a929cae2440999ff8a2c45277e195e6ddc6c3cda178ec7ae86b1f034bb45c23493efff526659c4170303004553d904ebd8d1fe7f9dd962770444e43e3f3b2e8e3eaf31478004748953b8c01bf420ba71e2484b29e7e2a907071ec23ba7de605dd72c370aee31412d194144bb6b32e469f8"
	payload1, _ := hex.DecodeString(raw1)
	data1, _ := hex.DecodeString(raw1[26:])
	packet1 := &packet{id: 2, opcode: 4, payload: payload1}
	bls1, _ := hex.DecodeString("5ad4a9517af8e7fe")
	var ls1 sessionID
	copy(ls1[:], bls1)

	type args struct {
		p *packet
	}
	tests := []struct {
		name    string
		args    args
		want    *packet
		wantErr error
	}{
		{
			name: "good control packet 1",
			args: args{packet1},
			want: &packet{
				id:              2,
				keyID:           0,
				opcode:          4,
				localSessionID:  ls1,
				remoteSessionID: sessionID{},
				payload:         data1,
			},
			wantErr: nil,
		},
		{
			name: "empty payload",
			args: args{
				p: &packet{
					id:      2,
					opcode:  4,
					payload: []byte{},
				},
			},
			want: &packet{
				id:      2,
				opcode:  4,
				payload: []byte{},
			},
			wantErr: errEmptyPayload,
		},
		{
			name: "non-control packet should fail",
			args: args{
				p: &packet{
					id:      1,
					opcode:  pDataV1,
					payload: []byte("a"),
				},
			},
			want: &packet{
				id:      1,
				opcode:  pDataV1,
				payload: []byte("a"),
			},
			wantErr: errBadInput,
		},
		{
			// TODO this case does corrupt the packet ID
			name: "parse till session id",
			args: args{
				p: &packet{
					id:     7,
					opcode: pControlV1,
					payload: []byte{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // sessionID
						0x00,                   // number of acks
						0x00, 0x00, 0x00, 0x07, // packetID
					},
				},
			},
			want: &packet{
				id:             7,
				opcode:         pControlV1,
				localSessionID: sessionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				payload:        []byte{},
			},
			wantErr: nil,
		},
		{
			name: "bad session id",
			args: args{
				p: &packet{
					id:     1,
					opcode: pControlV1,
					payload: []byte{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // incomplete session id
					},
				},
			},
			want: &packet{
				id:             1,
				opcode:         pControlV1,
				localSessionID: sessionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				payload:        []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			},
			wantErr: errBadInput,
		},
		{
			name: "not enough bytes for acks (eof)",
			args: args{
				p: &packet{
					id:     1,
					opcode: pControlV1,
					payload: []byte{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // good session id
					},
				},
			},
			want: &packet{
				id:             1,
				opcode:         pControlV1,
				localSessionID: sessionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				payload:        []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			},
			wantErr: errBadInput,
		},
		{
			name: "ack len ok, not enough bytes for ack id (eof)",
			args: args{
				p: &packet{
					id:     1,
					opcode: pControlV1,
					payload: []byte{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // good session id
						0x01, // EOF
					},
				},
			},
			want: &packet{
				id:             1,
				opcode:         pControlV1,
				localSessionID: sessionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				payload:        []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x01},
			},
			wantErr: errBadInput,
		},
		{
			name: "ack len ok, parse one ack id",
			args: args{
				p: &packet{
					id:     1,
					opcode: pControlV1,
					payload: []byte{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // good session id
						0x01,                   // one ack
						0x00, 0x00, 0x00, 0x42, // packet id of ack
					},
				},
			},
			want: &packet{
				id:             1,
				opcode:         pControlV1,
				localSessionID: sessionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				payload: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x01,
					0x00, 0x00, 0x00, 0x42,
				},
				acks: []packetID{0x42},
			},
			wantErr: errBadInput,
		},
		{
			name: "incomplete remote session id",
			args: args{
				p: &packet{
					id:     1,
					opcode: pControlV1,
					payload: []byte{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // good session id
						0x01,                   // one ack
						0x00, 0x00, 0x00, 0x42, // packet id of ack
					},
				},
			},
			want: &packet{
				id:             1,
				opcode:         pControlV1,
				localSessionID: sessionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				payload: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x01,
					0x00, 0x00, 0x00, 0x42,
				},
				acks: []packetID{0x42},
			},
			wantErr: errBadInput,
		},
		{
			name: "good remote session id",
			args: args{
				p: &packet{
					id:     1,
					opcode: pControlV1,
					payload: []byte{
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // good session id
						0x01,                   // one ack
						0x00, 0x00, 0x00, 0x42, // packet id of ack
						0xff, 0xfe, 0xfd, 0xfe,
						0xff, 0xfe, 0xfd, 0xfe, // remote session id
					},
				},
			},
			want: &packet{
				id:              1,
				opcode:          pControlV1,
				localSessionID:  sessionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				remoteSessionID: sessionID{0xff, 0xfe, 0xfd, 0xfe, 0xff, 0xfe, 0xfd, 0xfe},
				payload: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // session id
					0x01,                   // one ack
					0x00, 0x00, 0x00, 0x42, // packet id of ack
					0xff, 0xfe, 0xfd, 0xfe,
					0xff, 0xfe, 0xfd, 0xfe, // remote session id
				},
				acks: []packetID{0x42},
			},
			wantErr: errBadInput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseControlPacket(tt.args.p)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("parseControlPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.id != tt.want.id {
				t.Errorf("parseControlPacket() = got id %v, want %v", got.id, tt.want.id)
				return
			}
			if !bytes.Equal(got.payload, tt.want.payload) {
				t.Errorf("parseControlPacket() = got payload %v, want %v", got.payload, tt.want.payload)
				return
			}
			if !bytes.Equal(got.localSessionID[:], tt.want.localSessionID[:]) {
				t.Errorf("parseControlPacket() = got localSessionID %v, want %v", got.localSessionID[:], tt.want.localSessionID[:])
				return
			}
			if !bytes.Equal(got.remoteSessionID[:], tt.want.remoteSessionID[:]) {
				t.Errorf("parseControlPacket() = got remoteSessionID %v, want %v", got.remoteSessionID[:], tt.want.remoteSessionID[:])
				return
			}
		})
	}
}

func Test_newServerHardReset(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *serverHardReset
		wantErr error
	}{
		{
			name:    "good payload",
			args:    args{[]byte("not a payload")},
			want:    &serverHardReset{[]byte("not a payload")},
			wantErr: nil,
		},
		{
			name:    "empty",
			args:    args{[]byte{}},
			want:    nil,
			wantErr: errBadReset,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newServerHardReset(tt.args.b)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("newServerHardReset() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newServerHardReset() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseServerHardResetPacket(t *testing.T) {

	var goodSessionID sessionID
	goodPayload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	shortPayload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	copy(goodSessionID[:], goodPayload)

	type args struct {
		p *serverHardReset
	}
	tests := []struct {
		name    string
		args    args
		want    sessionID
		wantErr error
	}{
		{
			name: "good server hard reset",
			args: args{
				&serverHardReset{
					payload: append([]byte{0x40}, goodPayload...),
				},
			},
			want:    goodSessionID,
			wantErr: nil,
		},
		{
			name: "payload too short should fail",
			args: args{
				&serverHardReset{
					payload: append([]byte{0x40}, shortPayload...),
				},
			},
			want:    sessionID{},
			wantErr: errBadReset,
		},
		{
			name: "bad header should fail",
			args: args{
				&serverHardReset{
					payload: append([]byte{0x41}, goodPayload...),
				},
			},
			want:    sessionID{},
			wantErr: errBadReset,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseServerHardResetPacket(tt.args.p)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("parseServerHardResetPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseServerHardResetPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}
