// Package vpntest provides utilities for minivpn testing.
package vpntest

import (
	"reflect"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
)

func TestNewTestPacketFromString(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    *TestPacket
		wantErr bool
	}{
		{
			name: "parse a correct testpacket string",
			args: args{"[1] CONTROL_V1 +42ms"},
			want: &TestPacket{
				ID:     1,
				Opcode: model.P_CONTROL_V1,
				ACKs:   []int{},
				IAT:    time.Millisecond * 42,
			},
			wantErr: false,
		},
		{
			name: "parse a testpacket with acks",
			args: args{"[1] CONTROL_V1 (ack:0,1) +42ms"},
			want: &TestPacket{
				ID:     1,
				Opcode: model.P_CONTROL_V1,
				ACKs:   []int{0, 1},
				IAT:    time.Millisecond * 42,
			},
			wantErr: false,
		},
		{
			name: "empty acks part",
			args: args{"[1] CONTROL_V1 (ack:) +42ms"},
			want: &TestPacket{
				ID:     1,
				Opcode: model.P_CONTROL_V1,
				ACKs:   []int{},
				IAT:    time.Millisecond * 42,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTestPacketFromString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTestPacketFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTestPacketFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}
