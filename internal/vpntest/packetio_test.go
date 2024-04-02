package vpntest

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"

	// TODO: replace with stdlib slices after 1.21
	"golang.org/x/exp/slices"
)

func TestPacketLog_ACKs(t *testing.T) {
	tests := []struct {
		name string
		l    PacketLog
		want []int
	}{
		{
			name: "no acks",
			l:    []*LoggedPacket{},
			want: []int{},
		},
		{
			name: "one ack packet",
			l: []*LoggedPacket{
				{ACKs: []model.PacketID{0}},
			},
			want: []int{0},
		},
		{
			name: "one ack packet with two acks",
			l: []*LoggedPacket{
				{ACKs: []model.PacketID{1, 0}},
			},
			want: []int{1, 0},
		},
		{
			name: "two ack packets with two acks each",
			l: []*LoggedPacket{
				{ACKs: []model.PacketID{1, 0}},
				{ACKs: []model.PacketID{3, 2}},
			},
			want: []int{1, 0, 3, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.l.ACKs(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PacketLog.ACKs() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func TestPacketWriter_WriteExpandedSequence(t *testing.T) {
	tests := []struct {
		name    string
		seq     []string
		wantIDs []int
	}{
		{
			name:    "test range expansion",
			seq:     []string{"[1..5] CONTROL_V1 +1ms"},
			wantIDs: []int{1, 2, 3, 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan *model.Packet, 20)
			pw := NewPacketWriter(ch)
			pw.WriteSequence(tt.seq)

			got := make([]int, 0)
			for i := 0; i < len(tt.wantIDs); i++ {
				p := <-ch
				got = append(got, int(p.ID))
			}
			if !slices.Equal(got, tt.wantIDs) {
				t.Errorf("WriteExpandedSequence() got = %v, want %v", got, tt.wantIDs)
			}
		})
	}
}

func TestWitness_VerifyOrderedPayload(t *testing.T) {
	type args struct {
		packets []*model.Packet
		payload string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "simple payload, tree packets",
			args: args{
				packets: []*model.Packet{
					{
						ID:      1,
						Payload: []byte("aaa"),
					},
					{
						ID:      2,
						Payload: []byte("bbb"),
					},
					{
						ID:      3,
						Payload: []byte("ccc"),
					},
				},
				payload: "aaabbbccc",
			},
			want: true,
		},
		{
			name: "longer payload, two packets",
			args: args{
				packets: []*model.Packet{
					{
						ID:      1,
						Payload: []byte("aaaaaaaaaaaaaaa"),
					},
					{
						ID:      2,
						Payload: []byte("bbbbbbbbbbbbbbb"),
					},
				},
				payload: "aaaaaaaaaaaaaaabbbbbbbbbbbbbbb",
			},
			want: true,
		},
		{
			name: "empty payload no packets",
			args: args{
				packets: []*model.Packet{},
				payload: "",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan *model.Packet, 20)
			w := NewWitnessFromChannel(ch)

			for _, p := range tt.args.packets {
				ch <- p
			}
			t0 := time.Now()
			if got := w.VerifyOrderedPayload(tt.args.payload, t0); got != tt.want {
				t.Errorf("Witness.VerifyOrderedPayload() = %v, want %v", got, tt.want)
			}
			if w.Payload() != tt.args.payload {
				t.Errorf("Witness.Payload() = %v, want %v", w.Payload(), tt.want)
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

func TestPacketWriter_WriteSequenceWithFixedPayload(t *testing.T) {
	type args struct {
		seq     []string
		payload string
		size    int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "string payload with 2 char per packet",
			args: args{
				seq: []string{
					"[1] CONTROL_V1 +0ms",
					"[2] CONTROL_V1 +0ms",
					"[3] CONTROL_V1 +0ms",
					"[4] CONTROL_V1 +0ms",
					"[5] CONTROL_V1 +0ms",
					"[6] CONTROL_V1 +0ms",
					"[7] CONTROL_V1 +0ms",
					"[8] CONTROL_V1 +0ms",
					"[9] CONTROL_V1 +0ms",
					"[10] CONTROL_V1 +0ms",
				},
				payload: "aabbccddeeffgghhiijj",
				size:    2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan *model.Packet, 20)
			pw := NewPacketWriter(ch)
			pw.WriteSequenceWithFixedPayload(tt.args.seq, tt.args.payload, tt.args.size)

			got := ""
			for i := 0; i < len(tt.args.seq); i++ {
				p := <-ch
				got = got + string(p.Payload)
			}
			if got != tt.args.payload {
				t.Errorf("WriteSequenceWithFixedPayload: got = %v, want %v", got, tt.args.payload)
			}
		})
	}
}

// test that we're able to start/stop an echo server, and that
// it returns the same that is delivered.
func TestEchoServer_StartStop(t *testing.T) {
	type args struct {
		dataIn []*model.Packet
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no packets in",
			args: args{},
		},
		{
			name: "one packet in",
			args: args{
				[]*model.Packet{
					{ID: 1}},
			},
		},
		{
			name: "three packet in with payloads",
			args: args{
				[]*model.Packet{
					{ID: 1, Payload: []byte("aaa")},
					{ID: 2, Payload: []byte("bbb")},
					{ID: 3, Payload: []byte("ccc")},
				},
			},
		},
	}
	for _, tt := range tests {
		dataIn := make(chan *model.Packet, 1024)
		dataOut := make(chan *model.Packet, 1024)
		t.Run(tt.name, func(t *testing.T) {
			e := NewEchoServer(dataIn, dataOut)
			go e.Start()
			got := make([]*model.Packet, 0)
			for _, p := range tt.args.dataIn {
				dataIn <- p
			}
			for range tt.args.dataIn {
				p := <-dataOut
				got = append(got, p)
			}
			e.Stop()

			if len(got) != len(tt.args.dataIn) {
				t.Errorf("TestEchoServer_StartStop: got len = %v, want %v", len(got), len(tt.args.dataIn))
			}
			for i := range got {
				gotPacket := got[i]
				wantPacket := tt.args.dataIn[i]
				if gotPacket.ID != wantPacket.ID {
					t.Errorf("TestEchoServer_StartStop: packet %d:  got ID = %v, want %v", i, gotPacket.ID, wantPacket.ID)
				}
				if !bytes.Equal(gotPacket.Payload, wantPacket.Payload) {
					t.Errorf("TestEchoServer_StartStop: packet %d:  got Payload = %v, want Payload %v", i, gotPacket.Payload, wantPacket.Payload)
				}
			}
		})
	}
}
