package vpn

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

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
				buf = append(buf, []byte{0x00, 0x19}...)
				buf = append(buf, []byte("IV_VER=2.5.5\nIV_PROTO=2\n")...)
				buf = append(buf, 0x00)
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
				buf = append(buf, []byte("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-128-CBC,auth ,keysize 128,key-method 2,tls-client")...)
				// null-terminate + auth
				buf = append(buf, []byte{
					0x00,
					0x00, 0x01, 0x00,
					0x00, 0x01, 0x00}...)
				buf = append(buf, []byte{0x00, 0x19}...)
				buf = append(buf, []byte("IV_VER=2.5.5\nIV_PROTO=2\n")...)
				buf = append(buf, 0x00)
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

// Regression test for MIV-01-001
func Test_Crash_parseServerHardResetPacket(t *testing.T) {
	p := &serverHardReset{}
	parseServerHardResetPacket(p)
}
