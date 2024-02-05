package vpntest

import (
	"slices"
	"testing"
	"time"

	"github.com/apex/log"
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

func TestPacketRelay_RelayWithLosses(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	type fields struct {
		dataIn          chan *model.Packet
		dataOut         chan *model.Packet
		RemoteSessionID model.SessionID
	}
	type args struct {
		packetsIn []int
		losses    []int
		wantOut   []int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "zero loss",
			fields: fields{
				dataIn:  make(chan *model.Packet, 100),
				dataOut: make(chan *model.Packet, 100),
			},
			args: args{
				packetsIn: []int{1, 2, 3, 4},
				losses:    []int{},
				wantOut:   []int{1, 2, 3, 4},
			},
		},
		{
			name: "zero loss, repeated ids",
			fields: fields{
				dataIn:  make(chan *model.Packet, 100),
				dataOut: make(chan *model.Packet, 100),
			},
			args: args{
				packetsIn: []int{1, 2, 3, 4, 1},
				losses:    []int{},
				wantOut:   []int{1, 2, 3, 4, 1},
			},
		},
		{
			name: "loss for even ids",
			fields: fields{
				dataIn:  make(chan *model.Packet, 100),
				dataOut: make(chan *model.Packet, 100),
			},
			args: args{
				packetsIn: []int{1, 2, 3, 4, 5},
				losses:    []int{2, 4},
				wantOut:   []int{1, 3, 5},
			},
		},
		{
			name: "loss for first match",
			fields: fields{
				dataIn:  make(chan *model.Packet, 100),
				dataOut: make(chan *model.Packet, 100),
			},
			args: args{
				packetsIn: []int{1, 2, 3, 4, 5, 1, 2},
				losses:    []int{1, 2},
				wantOut:   []int{3, 4, 5, 1, 2},
			},
		},
		{
			name: "loss for two matches",
			fields: fields{
				dataIn:  make(chan *model.Packet, 100),
				dataOut: make(chan *model.Packet, 100),
			},
			args: args{
				packetsIn: []int{1, 2, 3, 2, 1, 4, 5, 1, 2},
				losses:    []int{1, 1, 2, 2},
				wantOut:   []int{3, 4, 5, 1, 2},
			},
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			pr := NewPacketRelay(
				tt.fields.dataIn,
				tt.fields.dataOut,
			)
			go pr.RelayWithLosses(tt.args.losses)
			writer := NewPacketWriter(tt.fields.dataIn)
			for _, id := range tt.args.packetsIn {
				writer.WritePacketWithID(id)
			}
			got := readPacketIDSequence(tt.fields.dataOut, len(tt.args.wantOut))
			pr.Stop()
			if !slices.Equal(got, tt.args.wantOut) {
				t.Errorf("relayWithLosses: got = %v, want %v", got, tt.args.wantOut)
			}
		})
	}
}

func readPacketIDSequence(ch chan *model.Packet, wantLen int) []int {
	var got []int
	for {
		pkt := <-ch
		got = append(got, int(pkt.ID))
		if len(got) >= wantLen {
			break
		}
	}
	return got
}
