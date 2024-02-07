package vpntest

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
)

func TestPacketReaderWriter(t *testing.T) {
	type args struct {
		input  []string
		output []int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "simple input, simple output",
			args: args{
				input: []string{
					"[1] CONTROL_V1 +0ms",
					"[2] CONTROL_V1 +0ms",
					"[3] CONTROL_V1 +0ms",
				},
				output: []int{1, 2, 3},
			},
			want: true,
		},
		{
			name: "reverse in, reverse out",
			args: args{
				input: []string{
					"[3] CONTROL_V1 +0ms",
					"[2] CONTROL_V1 +0ms",
					"[1] CONTROL_V1 +0ms",
				},
				output: []int{3, 2, 1},
			},
			want: true,
		},
		{
			name: "holes in, holes out",
			args: args{
				input: []string{
					"[0] CONTROL_V1 +0ms",
					"[10] CONTROL_V1 +0ms",
					"[1] CONTROL_V1 +0ms",
					"[20] CONTROL_V1 +0ms",
				},
				output: []int{0, 10, 1, 20},
			},
			want: true,
		},
		{
			name: "mismatch returns false",
			args: args{
				input: []string{
					"[0] CONTROL_V1 +0ms",
					"[1] CONTROL_V1 +0ms",
				},
				output: []int{1, 0},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan *model.Packet)
			writer := NewPacketWriter(ch)
			go writer.WriteSequence(tt.args.input)
			reader := NewPacketReader(ch)
			if ok := reader.WaitForSequence(tt.args.output, time.Now()); ok != tt.want {
				got := reader.Log().IDSequence()
				t.Errorf("PacketReader.WaitForSequence() = %v, want %v", got, tt.args.output)
			}
		})
	}
}
