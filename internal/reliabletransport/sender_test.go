package reliabletransport

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
)

func idSequence(s inflightSequence) []model.PacketID {
	ids := make([]model.PacketID, 0)
	for _, p := range s {
		ids = append(ids, p.packet.ID)
	}
	return ids
}

//
// tests for reliableSender
//

func Test_newReliableSender(t *testing.T) {
	s := newReliableSender(log.Log, make(chan incomingPacketSeen))
	if s.logger == nil {
		t.Errorf("newReliableSender(): expected non nil logger")
	}
	if s.incomingSeen == nil {
		t.Errorf("newReliableSender(): expected non nil incomingSeen")
	}
}

func Test_reliableSender_TryInsertOutgoingPacket(t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}

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
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}

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

// Here we test injecting different ACKs for a given in flight queue (with expired deadlines or not),
// and we check what do we get ready to send.
func Test_reliableSender_maybeEvictOrMarkWithHigherACK(t *testing.T) {
	t0 := time.Date(1984, time.January, 1, 0, 0, 0, 0, time.UTC)

	type fields struct {
		inFlight []*inFlightPacket
	}
	type args struct {
		acked model.PacketID
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantSequence []model.PacketID
	}{
		{
			name: "empty ack does not evict anything",
			fields: fields{[]*inFlightPacket{
				{packet: &model.Packet{ID: 1}},
			}},
			args:         args{},
			wantSequence: []model.PacketID{1},
		},
		{
			name: "one ack evicts the matching inflight packet",
			fields: fields{[]*inFlightPacket{
				{packet: &model.Packet{ID: 1}},
				{packet: &model.Packet{ID: 2}},
				{packet: &model.Packet{ID: 3}},
				{packet: &model.Packet{ID: 4}},
			}},
			args:         args{model.PacketID(1)},
			wantSequence: []model.PacketID{2, 3, 4},
		},
		{
			name: "high ack evicts only that packet",
			fields: fields{[]*inFlightPacket{
				{packet: &model.Packet{ID: 1}},
				{packet: &model.Packet{ID: 2}},
				{packet: &model.Packet{ID: 3}},
				{packet: &model.Packet{ID: 4}},
			}},
			args: args{
				model.PacketID(4),
			},
			wantSequence: []model.PacketID{1, 2, 3},
		},
		{
			name: "high ack evicts that packet, and gets a fast rxmit if >=3",
			fields: fields{[]*inFlightPacket{
				{
					// expired, should be returned
					packet:   &model.Packet{ID: 1},
					deadline: t0.Add(-1 * time.Millisecond),
				},
				{
					// this one should get returned too, will get the ack counter == 3
					packet:     &model.Packet{ID: 2},
					deadline:   t0.Add(20 * time.Millisecond),
					higherACKs: 2,
				},
				{
					// this one has counter to zero and not expired, should not be returned
					packet:     &model.Packet{ID: 3},
					deadline:   t0.Add(20 * time.Millisecond),
					higherACKs: 0,
				},
				{
					// this one is the one we're evicting so who cares
					packet: &model.Packet{ID: 4},
				},
			}},
			args: args{
				// let's evict this poor packet!
				model.PacketID(4),
			},
			wantSequence: []model.PacketID{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableSender{
				logger:   log.Log,
				inFlight: tt.fields.inFlight,
			}
			r.maybeEvictOrMarkWithHigherACK(tt.args.acked)
			gotToSend := idSequence(inflightSequence(r.inFlight).readyToSend(t0))
			if !slices.Equal(gotToSend, tt.wantSequence) {
				t.Errorf("reliableSender.maybeEvictOrMarkWithHigherACK() = %v, want %v", gotToSend, tt.wantSequence)
			}
		})
	}
}

func Test_reliableSender_hasPendingACKs(t *testing.T) {
	type fields struct {
		pendingACKsToSend *ackSet
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "empty acksset returns false",
			fields: fields{
				newACKSet(),
			},
			want: false,
		},
		{
			name: "not empty ackset returns true",
			fields: fields{
				newACKSet(1),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableSender{
				logger:            log.Log,
				pendingACKsToSend: tt.fields.pendingACKsToSend,
			}
			if got := r.hasPendingACKs(); got != tt.want {
				t.Errorf("reliableSender.hasPendingACKs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reliableSender_shouldWakeupAfterACK(t *testing.T) {
	t0 := time.Date(1984, time.January, 1, 0, 0, 0, 0, time.UTC)

	type fields struct {
		inflight          []*inFlightPacket
		pendingACKsToSend *ackSet
	}
	type args struct {
		t time.Time
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		want         bool
		wantDuration time.Duration
	}{
		{
			name: "empty ackset returns false",
			fields: fields{
				pendingACKsToSend: newACKSet(),
			},
			args:         args{t0},
			want:         false,
			wantDuration: time.Minute,
		},
		{
			name: "len(ackset)=2 returns true",
			fields: fields{
				pendingACKsToSend: newACKSet(1, 2),
			},
			args:         args{t0},
			want:         true,
			wantDuration: time.Nanosecond,
		},
		{
			name: "len(ackset)=1 returns grace period",
			fields: fields{
				pendingACKsToSend: newACKSet(1),
			},
			args:         args{t0},
			want:         true,
			wantDuration: gracePeriodForOutgoingACKs,
		},
		{
			name: "len(ackset)=1 returns lower deadline if below grace period",
			fields: fields{
				inflight: []*inFlightPacket{
					{
						packet:   &model.Packet{ID: 1},
						deadline: t0.Add(5 * time.Millisecond),
					},
					{
						packet:   &model.Packet{ID: 2},
						deadline: t0.Add(10 * time.Millisecond),
					}},
				pendingACKsToSend: newACKSet(1),
			},
			args:         args{t0},
			want:         true,
			wantDuration: time.Millisecond * 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableSender{
				logger:            log.Log,
				inFlight:          tt.fields.inflight,
				pendingACKsToSend: tt.fields.pendingACKsToSend,
			}
			got, gotDuration := r.shouldWakeupAfterACK(tt.args.t)
			if got != tt.want {
				t.Errorf("reliableSender.shouldWakeupAfterACK() got = %v, want %v", got, tt.want)
			}
			if gotDuration != tt.wantDuration {
				t.Errorf("reliableSender.shouldWakeupAfterACK() gotDuration = %v, want %v", gotDuration, tt.wantDuration)
			}
		})
	}
}

//
// tests for ackSet
//

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
