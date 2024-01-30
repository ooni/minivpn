package reliabletransport

import (
	"reflect"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
)

//
// tests for reliableReceiver
//

// testIncomingPacket is a sequentialPacket for testing incomingPackets
type testIncomingPacket struct {
	id   model.PacketID
	acks []model.PacketID
}

func (ip *testIncomingPacket) ID() model.PacketID {
	return ip.id
}

func (ip *testIncomingPacket) ExtractACKs() []model.PacketID {
	return ip.acks
}

func (ip *testIncomingPacket) Packet() *model.Packet {
	return &model.Packet{ID: ip.id}
}

var _ sequentialPacket = &testIncomingPacket{}

func Test_reliableQueue_MaybeInsertIncoming(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	type fields struct {
		incomingPackets incomingSequence
	}
	type args struct {
		p *testIncomingPacket
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "empty incoming, insert one",
			fields: fields{
				incomingPackets: []sequentialPacket{},
			},
			args: args{
				&testIncomingPacket{id: 1},
			},
			want: true,
		},
		{
			name: "almost full incoming, insert one",
			fields: fields{
				incomingPackets: []sequentialPacket{
					&testIncomingPacket{id: 1},
					&testIncomingPacket{id: 2},
					&testIncomingPacket{id: 3},
					&testIncomingPacket{id: 4},
					&testIncomingPacket{id: 5},
					&testIncomingPacket{id: 6},
					&testIncomingPacket{id: 7},
					&testIncomingPacket{id: 8},
					&testIncomingPacket{id: 9},
					&testIncomingPacket{id: 10},
					&testIncomingPacket{id: 11},
				},
			},
			args: args{
				&testIncomingPacket{id: 12},
			},
			want: true,
		},
		{
			name: "full incoming, cannot insert",
			fields: fields{
				incomingPackets: []sequentialPacket{
					&testIncomingPacket{id: 1},
					&testIncomingPacket{id: 2},
					&testIncomingPacket{id: 3},
					&testIncomingPacket{id: 4},
					&testIncomingPacket{id: 5},
					&testIncomingPacket{id: 6},
					&testIncomingPacket{id: 7},
					&testIncomingPacket{id: 8},
					&testIncomingPacket{id: 9},
					&testIncomingPacket{id: 10},
					&testIncomingPacket{id: 11},
					&testIncomingPacket{id: 12},
				},
			},
			args: args{
				&testIncomingPacket{id: 13},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableReceiver{
				logger:          log.Log,
				incomingPackets: tt.fields.incomingPackets,
			}
			if got := r.MaybeInsertIncoming(tt.args.p.Packet()); got != tt.want {
				t.Errorf("reliableQueue.MaybeInsertIncoming() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reliableQueue_NextIncomingSequence(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	type fields struct {
		lastConsumed    model.PacketID
		incomingPackets incomingSequence
	}
	tests := []struct {
		name   string
		fields fields
		want   incomingSequence
	}{
		{
			name: "empty sequence",
			fields: fields{
				incomingPackets: []sequentialPacket{},
				lastConsumed:    model.PacketID(0),
			},
			want: []sequentialPacket{},
		},
		{
			name: "single packet",
			fields: fields{
				lastConsumed: model.PacketID(0),
				incomingPackets: []sequentialPacket{
					&testIncomingPacket{id: 1},
				},
			},
			want: []sequentialPacket{
				&testIncomingPacket{id: 1},
			},
		},
		{
			name: "series of sequential packets",
			fields: fields{
				lastConsumed: model.PacketID(0),
				incomingPackets: []sequentialPacket{
					&testIncomingPacket{id: 1},
					&testIncomingPacket{id: 2},
					&testIncomingPacket{id: 3},
				},
			},
			want: []sequentialPacket{
				&testIncomingPacket{id: 1},
				&testIncomingPacket{id: 2},
				&testIncomingPacket{id: 3},
			},
		},
		{
			name: "series of sequential packets with hole",
			fields: fields{
				lastConsumed: model.PacketID(0),
				incomingPackets: []sequentialPacket{
					&testIncomingPacket{id: 1},
					&testIncomingPacket{id: 2},
					&testIncomingPacket{id: 3},
					&testIncomingPacket{id: 5},
				},
			},
			want: []sequentialPacket{
				&testIncomingPacket{id: 1},
				&testIncomingPacket{id: 2},
				&testIncomingPacket{id: 3},
			},
		},
		{
			name: "series of sequential packets with hole, lastConsumed higher",
			fields: fields{
				lastConsumed: model.PacketID(10),
				incomingPackets: []sequentialPacket{
					&testIncomingPacket{id: 1},
					&testIncomingPacket{id: 2},
					&testIncomingPacket{id: 3},
					&testIncomingPacket{id: 5},
				},
			},
			want: []sequentialPacket{},
		},
		{
			name: "series of sequential packets with hole, lastConsumed higher, some above",
			fields: fields{
				lastConsumed: model.PacketID(10),
				incomingPackets: []sequentialPacket{
					&testIncomingPacket{id: 1},
					&testIncomingPacket{id: 2},
					&testIncomingPacket{id: 10},
					&testIncomingPacket{id: 11},
					&testIncomingPacket{id: 12},
					&testIncomingPacket{id: 20},
				},
			},
			want: []sequentialPacket{
				&testIncomingPacket{id: 11},
				&testIncomingPacket{id: 12},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableReceiver{
				lastConsumed:    tt.fields.lastConsumed,
				incomingPackets: tt.fields.incomingPackets,
			}
			if got := r.NextIncomingSequence(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reliableQueue.NextIncomingSequence() = %v, want %v", got, tt.want)
			}
		})
	}
}
