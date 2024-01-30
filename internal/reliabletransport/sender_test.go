package reliabletransport

import (
	"reflect"
	"slices"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

//
// tests for reliableSender
//

func Test_reliableSender_TryInsertOutgoingPacket(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	type fields struct {
		inFlight inflightSequence
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
			name: "insert on empty array",
			fields: fields{
				inFlight: inflightSequence([]*inFlightPacket{}),
			},
			args: args{
				p: &model.Packet{ID: 1},
			},
			want: true,
		},
		{
			name: "insert on full array",
			fields: fields{
				inFlight: inflightSequence([]*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 2}},
					{packet: &model.Packet{ID: 3}},
					{packet: &model.Packet{ID: 4}},
					{packet: &model.Packet{ID: 5}},
					{packet: &model.Packet{ID: 6}},
				}),
			},
			args: args{
				p: &model.Packet{ID: 7},
			},
			want: false,
		},
		{
			name: "insert on almost full array",
			fields: fields{
				inFlight: inflightSequence([]*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 2}},
					{packet: &model.Packet{ID: 3}},
					{packet: &model.Packet{ID: 4}},
					{packet: &model.Packet{ID: 5}},
				}),
			},
			args: args{
				p: &model.Packet{ID: 6},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableSender{
				logger:   log.Log,
				inFlight: tt.fields.inFlight,
			}
			if got := r.TryInsertOutgoingPacket(tt.args.p); got != tt.want {
				t.Errorf("reliableSender.TryInsertOutgoingPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reliableSender_NextPacketIDsToACK(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	type fields struct {
		pendingACKsToSend []model.PacketID
	}
	tests := []struct {
		name   string
		fields fields
		want   []model.PacketID
	}{
		{
			name: "empty array",
			fields: fields{
				pendingACKsToSend: []model.PacketID{},
			},
			want: []model.PacketID{},
		},
		{
			name: "single element",
			fields: fields{
				pendingACKsToSend: []model.PacketID{11},
			},
			want: []model.PacketID{11},
		},
		{
			name: "tree elements",
			fields: fields{
				pendingACKsToSend: []model.PacketID{12, 11, 13},
			},
			want: []model.PacketID{11, 12, 13},
		},
		{
			name: "five elements",
			fields: fields{
				pendingACKsToSend: []model.PacketID{15, 12, 14, 13, 11},
			},
			want: []model.PacketID{11, 12, 13, 14},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableSender{
				logger:            log.Log,
				pendingACKsToSend: newACKSet(tt.fields.pendingACKsToSend...),
			}
			if got := r.NextPacketIDsToACK(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reliableSender.NextPacketIDsToACK() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ackSet_maybeAdd(t *testing.T) {
	type fields struct {
		m map[model.PacketID]bool
	}
	type args struct {
		id optional.Value[model.PacketID]
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *ackSet
	}{
		{
			name:   "can add on empty set",
			fields: fields{newACKSet().m},
			args:   args{optional.Some(model.PacketID(1))},
			want:   newACKSet(1),
		},
		{
			name:   "add duplicate on empty set",
			fields: fields{newACKSet(1).m},
			args:   args{optional.Some(model.PacketID(1))},
			want:   newACKSet(1),
		},
		{
			name:   "cannot add beyond capacity",
			fields: fields{newACKSet(1, 2, 3, 4, 5, 6, 7, 8).m},
			args:   args{optional.Some(model.PacketID(10))},
			want:   newACKSet(1, 2, 3, 4, 5, 6, 7, 8),
		},
		{
			name:   "order does not matter",
			fields: fields{newACKSet(3, 2, 1).m},
			args:   args{optional.Some(model.PacketID(4))},
			want:   newACKSet(1, 2, 3, 4),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := &ackSet{
				m: tt.fields.m,
			}
			if got := as.maybeAdd(tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ackSet.maybeAdd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ackSet_nextToACK(t *testing.T) {
	type fields struct {
		m map[model.PacketID]bool
	}
	tests := []struct {
		name   string
		fields fields
		want   []model.PacketID
	}{
		{
			name:   "get all if you have <4",
			fields: fields{newACKSet(1, 2, 3).m},
			want:   []model.PacketID{1, 2, 3},
		},
		{
			name:   "get all if you have 4",
			fields: fields{newACKSet(1, 2, 3, 4).m},
			want:   []model.PacketID{1, 2, 3, 4},
		},
		{
			name:   "get 2 if you have 2, sorted",
			fields: fields{newACKSet(4, 1).m},
			want:   []model.PacketID{1, 4},
		},
		{
			name:   "get first 4 if you have >4, sorted",
			fields: fields{newACKSet(5, 6, 8, 3, 2, 4, 1).m},
			want:   []model.PacketID{1, 2, 3, 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := &ackSet{
				m: tt.fields.m,
			}
			if got := as.nextToACK(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ackSet.nextToACK() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ackSet_nextToACK_empties_set(t *testing.T) {
	acks := newACKSet(1, 2, 3, 5, 4, 6, 7, 10, 9, 8)

	want1 := []model.PacketID{1, 2, 3, 4}
	want2 := []model.PacketID{5, 6, 7, 8}
	want3 := []model.PacketID{9, 10}

	if got := acks.nextToACK(); !reflect.DeepEqual(got, want1) {
		t.Errorf("ackSet.nextToACK() = %v, want %v", got, want1)
	}
	if got := acks.nextToACK(); !reflect.DeepEqual(got, want2) {
		t.Errorf("ackSet.nextToACK() = %v, want %v", got, want1)
	}
	if got := acks.nextToACK(); !reflect.DeepEqual(got, want3) {
		t.Errorf("ackSet.nextToACK() = %v, want %v", got, want3)
	}
}

// test the combined behavior of reacting to an incoming packet and checking
// what's left in the in flight queue and what's left in the queue of pending acks.
func Test_reliableSender_OnIncomingPacketSeen(t *testing.T) {

	idSequence := func(ifp []*inFlightPacket) []model.PacketID {
		ids := make([]model.PacketID, 0)
		for _, p := range ifp {
			ids = append(ids, p.packet.ID)
		}
		return ids
	}

	type fields struct {
		pendingacks *ackSet
		inflight    []*inFlightPacket
	}
	type args struct {
		seen []incomingPacketSeen
	}
	type want struct {
		acks     []model.PacketID
		inflight []model.PacketID
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "empty seen does not change anything",
			fields: fields{
				pendingacks: newACKSet(),
				inflight: []*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 2}}},
			},
			args: args{},
			want: want{inflight: []model.PacketID{1, 2}},
		},
		{
			name: "ack for 1 evicts in-flight packet 1",
			fields: fields{
				pendingacks: newACKSet(),
				inflight: []*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 2}}},
			},
			args: args{[]incomingPacketSeen{
				{
					acks: optional.Some([]model.PacketID{model.PacketID(1)}),
				},
			},
			},
			want: want{inflight: []model.PacketID{2}},
		},
		{
			name: "ack for 2,1 evicts in-flight packets 1,2",
			fields: fields{
				pendingacks: newACKSet(),
				inflight: []*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 2}}},
			},
			args: args{[]incomingPacketSeen{
				{
					acks: optional.Some([]model.PacketID{
						model.PacketID(2),
						model.PacketID(1),
					}),
				},
			},
			},
			want: want{inflight: []model.PacketID{}},
		},
		{
			name: "ack for non-existent packet does not evict anything",
			fields: fields{
				pendingacks: newACKSet(),
				inflight: []*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 2}},
					{packet: &model.Packet{ID: 3}}},
			},
			args: args{[]incomingPacketSeen{
				{
					acks: optional.Some([]model.PacketID{
						model.PacketID(10),
					}),
				},
			},
			},
			want: want{inflight: []model.PacketID{1, 2, 3}},
		},
		{
			name: "duplicated ack can only evict once",
			fields: fields{
				pendingacks: newACKSet(),
				inflight: []*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 2}},
					{packet: &model.Packet{ID: 3}},
					{packet: &model.Packet{ID: 4}}},
			},
			args: args{[]incomingPacketSeen{
				{
					acks: optional.Some([]model.PacketID{
						model.PacketID(3),
						model.PacketID(3),
					}),
				},
			},
			},
			want: want{inflight: []model.PacketID{1, 2, 4}},
		},
		{
			name: "seen id adds to pending ids to ack, plus ack evicts",
			fields: fields{
				pendingacks: newACKSet(4, 6),
				inflight: []*inFlightPacket{
					{packet: &model.Packet{ID: 1}},
					{packet: &model.Packet{ID: 3}}},
			},
			args: args{[]incomingPacketSeen{
				// a packet seen with ID + acks
				{
					id: optional.Some(model.PacketID(2)),
					acks: optional.Some([]model.PacketID{
						model.PacketID(1),
					}),
				},
			},
			},
			want: want{
				acks:     []model.PacketID{2, 4, 6},
				inflight: []model.PacketID{3}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableSender{
				logger:            log.Log,
				inFlight:          tt.fields.inflight,
				pendingACKsToSend: tt.fields.pendingacks,
			}
			for _, seen := range tt.args.seen {
				r.OnIncomingPacketSeen(seen)
			}
			if gotACKs := r.NextPacketIDsToACK(); !slices.Equal(gotACKs, tt.want.acks) {
				t.Errorf("reliableSender.NextPacketIDsToACK() = %v, want %v", gotACKs, tt.want.acks)
			}
			if seq := idSequence(r.inFlight); !slices.Equal(seq, tt.want.inflight) {
				t.Errorf("reliableSender.NextPacketIDsToACK() = %v, want %v", seq, tt.want.inflight)
			}
		})
	}
}

// TODO: exercise maybeEvict + withHigherACKs
