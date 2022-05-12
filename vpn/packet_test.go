package vpn

import (
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

func Test_newServerControlMessageFromBytes(t *testing.T) {
	type args struct {
		buf []byte
	}
	tests := []struct {
		name string
		args args
		want *serverControlMessage
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newServerControlMessageFromBytes(tt.args.buf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newServerControlMessageFromBytes() = %v, want %v", got, tt.want)
			}
		})
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
	tests := []struct {
		name string
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodePushRequestAsBytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodePushRequestAsBytes() = %v, want %v", got, tt.want)
			}
		})
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
