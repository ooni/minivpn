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

func Test_newReliableReceiver(t *testing.T) {
	rr := newReliableReceiver(log.Log, make(chan incomingPacketSeen))
	if rr.logger == nil {
		t.Errorf("newReliableReceiver() should not have nil logger")
	}
	if rr.incomingPackets == nil {
		t.Errorf("newReliableReceiver() should not have nil incomingPackets ch")
	}
	if rr.lastConsumed != 0 {
		t.Errorf("newReliableReceiver() should have lastConsumed == 0")
	}
}

func Test_reliableQueue_MaybeInsertIncoming(t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}

	type fields struct {
		incomingPackets incomingSequence
	}
	type args struct {
		p *model.Packet
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
				incomingPackets: make([]*model.Packet, 0),
			},
			args: args{
				&model.Packet{ID: 1},
			},
			want: true,
		},
		{
			name: "almost full incoming, insert one",
			fields: fields{
				incomingPackets: []*model.Packet{
					{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4},
					{ID: 5}, {ID: 6}, {ID: 7}, {ID: 8},
					{ID: 9}, {ID: 10}, {ID: 11},
				},
			},
			args: args{&model.Packet{ID: 12}},
			want: true,
		},
		{
			name: "full incoming, cannot insert",
			fields: fields{
				incomingPackets: []*model.Packet{
					{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4},
					{ID: 5}, {ID: 6}, {ID: 7}, {ID: 8},
					{ID: 9}, {ID: 10}, {ID: 11}, {ID: 12},
				},
			},
			args: args{
				&model.Packet{ID: 13},
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
			if got := r.MaybeInsertIncoming(tt.args.p); got != tt.want {
				t.Errorf("reliableQueue.MaybeInsertIncoming() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reliableQueue_NextIncomingSequence(t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}

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
				incomingPackets: []*model.Packet{},
				lastConsumed:    model.PacketID(0),
			},
			want: []*model.Packet{},
		},
		{
			name: "single packet",
			fields: fields{
				lastConsumed: model.PacketID(0),
				incomingPackets: []*model.Packet{
					{ID: 1},
				},
			},
			want: []*model.Packet{
				{ID: 1},
			},
		},
		{
			name: "series of sequential packets",
			fields: fields{
				lastConsumed:    model.PacketID(0),
				incomingPackets: []*model.Packet{{ID: 1}, {ID: 2}, {ID: 3}},
			},
			want: []*model.Packet{{ID: 1}, {ID: 2}, {ID: 3}},
		},
		{
			name: "series of sequential packets with hole",
			fields: fields{
				lastConsumed:    model.PacketID(0),
				incomingPackets: []*model.Packet{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 5}},
			},
			want: []*model.Packet{{ID: 1}, {ID: 2}, {ID: 3}},
		},
		{
			name: "series of sequential packets with hole, lastConsumed higher",
			fields: fields{
				lastConsumed:    model.PacketID(10),
				incomingPackets: []*model.Packet{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 5}},
			},
			want: []*model.Packet{},
		},
		{
			name: "series of sequential packets with hole, lastConsumed higher, some above",
			fields: fields{
				lastConsumed:    model.PacketID(10),
				incomingPackets: []*model.Packet{{ID: 1}, {ID: 2}, {ID: 10}, {ID: 11}, {ID: 12}, {ID: 20}},
			},
			want: []*model.Packet{{ID: 11}, {ID: 12}},
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
