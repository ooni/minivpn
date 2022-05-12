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
		// TODO: Add test cases.
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

func Test_encodePushRequestAsBytes(t *testing.T) {
	got := encodePushRequestAsBytes()
	if !bytes.Equal(got[:len(got)-1], []byte("PUSH_REQUEST")) {
		t.Errorf("encodePushRequestAsBytes() = %v", got)
	}
	if got[len(got)-1] != 0x00 {
		t.Errorf("encodePushRequestAsBytes(): expected trailing null byte")
	}

}

func Test_newPacketFromBytes(t *testing.T) {
	type args struct {
		buf []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *packet
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newPacketFromBytes(tt.args.buf)
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

// --------------- adding
