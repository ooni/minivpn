package vpn

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

/*
func Test_isControlOpcode(t *testing.T) {
	type args struct {
		b byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"hardResetServer", args{byte(pControlHardResetServerV2)}, true},
		{"control1", args{byte(pControlV1)}, true},
		{"zero", args{0}, false},
		{"ones", args{255}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isControlOpcode(tt.args.b); got != tt.want {
				t.Errorf("isControlOpcode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isDataOpcode(t *testing.T) {
	type args struct {
		b byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"data", args{byte(pDataV1)}, true},
		{"zero", args{byte(0)}, false},
		{"ones", args{byte(255)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDataOpcode(tt.args.b); got != tt.want {
				t.Errorf("isDataOpcode() = %v, want %v", got, tt.want)
			}
		})
	}
}
*/

func Test_packet_Bytes(t *testing.T) {
	got := (&packet{opcode: pACKV1}).Bytes()
	want := []byte{40, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("newPacketFromBytes() = %v, want %v", got, want)
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

func Test_sessionID_Bytes(t *testing.T) {
	// TODO this test is stupid
	tests := []struct {
		name string
		s    *sessionID
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sessionID.Bytes() = %v, want %v", got, tt.want)
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
	if !bytes.Equal(wantRandom1, gotKeySource.r1) {
		t.Errorf("parseServerControlMessage(). got ks.r1 = %v, want ks.r1 %v", gotKeySource.r1, wantRandom1)
	}
	if !bytes.Equal(wantRandom2, gotKeySource.r2) {
		t.Errorf("parseServerControlMessage(). got ks.r2 = %v, want ks.r2 %v", gotKeySource.r2, wantRandom2)
	}
}

func Test_encodeClientControlMessageAsBytes(t *testing.T) {
	manyA := bytes.Repeat([]byte{0x65}, 32)
	manyB := bytes.Repeat([]byte{0x66}, 32)
	manyC := bytes.Repeat([]byte{0x67}, 32)

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
				buf = append(buf, manyC...)
				buf = append(buf, manyA...)
				buf = append(buf, manyB...)
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
				buf = append(buf, manyC...)
				buf = append(buf, manyA...)
				buf = append(buf, manyB...)
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

// --------------- adding tests below, need to reorder ------------------------------ //

func Test_parseControlPacket(t *testing.T) {
	raw1 := "5ad4a9517af8e7fe000000000296f517f943d32a11fc8463b8594ae7d3523b627d8c9444aac2def81a13bea2e037aecbd158bdf50ed16e800829a929cae2440999ff8a2c45277e195e6ddc6c3cda178ec7ae86b1f034bb45c23493efff526659c4170303004553d904ebd8d1fe7f9dd962770444e43e3f3b2e8e3eaf31478004748953b8c01bf420ba71e2484b29e7e2a907071ec23ba7de605dd72c370aee31412d194144bb6b32e469f8"
	payload1, _ := hex.DecodeString(raw1)
	data1, _ := hex.DecodeString(raw1[26:])
	p1 := &packet{id: 2, opcode: 4, payload: payload1}
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
		wantErr bool
	}{
		{
			"good control packet 1",
			args{p1},
			&packet{
				id:              2,
				keyID:           0,
				opcode:          4,
				localSessionID:  ls1,
				remoteSessionID: sessionID{},
				payload:         data1,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseControlPacket(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseControlPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.payload, tt.want.payload) {
				t.Errorf("parseControlPacket() = got %v, want %v", got.payload, tt.want.payload)
			}
			if !reflect.DeepEqual(got.localSessionID, tt.want.localSessionID) {
				t.Errorf("parseControlPacket() = got %v, want %v", got.payload, tt.want.payload)
			}
			if !reflect.DeepEqual(got.remoteSessionID, tt.want.remoteSessionID) {
				t.Errorf("parseControlPacket() = got %v, want %v", got.payload, tt.want.payload)
			}
		})
	}
}
