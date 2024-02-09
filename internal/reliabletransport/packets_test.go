package reliabletransport

import (
	"reflect"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
)

func Test_inFlightPacket_backoff(t *testing.T) {
	type fields struct {
		retries int
	}
	tests := []struct {
		name   string
		fields fields
		want   time.Duration
	}{
		{
			name:   "retries=0",
			fields: fields{0},
			want:   time.Second,
		},
		{
			name:   "retries=1",
			fields: fields{1},
			want:   time.Second * 2,
		},
		{
			name:   "retries=2",
			fields: fields{2},
			want:   time.Second * 4,
		},
		{
			name:   "retries=3",
			fields: fields{3},
			want:   time.Second * 8,
		},
		{
			name:   "retries=4",
			fields: fields{4},
			want:   time.Second * 16,
		},
		{
			name:   "retries=5",
			fields: fields{5},
			want:   time.Second * 32,
		},
		{
			name:   "retries=6",
			fields: fields{6},
			want:   time.Second * 60,
		},
		{
			name:   "retries=10",
			fields: fields{10},
			want:   time.Second * 60,
		},
		{
			name:   "retries=6",
			fields: fields{6},
			want:   time.Second * 60,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &inFlightPacket{
				retries: tt.fields.retries,
			}
			if got := p.backoff(); got != tt.want {
				t.Errorf("inFlightPacket.backoff() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_inFlightPacket_ScheduleForRetransmission(t *testing.T) {
	p0 := newInFlightPacket(&model.Packet{})
	if p0.retries != 0 {
		t.Errorf("inFlightPacket.retries should be 0")
	}
	t0 := time.Now()
	p0.ScheduleForRetransmission(t0)
	if p0.retries != 1 {
		t.Errorf("inFlightPacket.retries should be 0")
	}
	if p0.deadline != t0.Add(time.Second*2) {
		t.Errorf("inFlightPacket.deadline should be 2s in the future")
	}
	// schedule twice now
	p0.ScheduleForRetransmission(t0)
	p0.ScheduleForRetransmission(t0)
	if p0.retries != 3 {
		t.Errorf("inFlightPacket.retries should be 3")
	}
	if p0.deadline != t0.Add(time.Second*8) {
		t.Errorf("inFlightPacket.deadline should be 8s in the future")
	}
	// schedule twice again
	p0.ScheduleForRetransmission(t0)
	p0.ScheduleForRetransmission(t0)
	if p0.retries != 5 {
		t.Errorf("inFlightPacket.retries should be 5")
	}
	if p0.deadline != t0.Add(time.Second*32) {
		t.Errorf("inFlightPacket.deadline should be 32s in the future")
	}
}

func Test_inflightSequence_nearestDeadlineTo(t *testing.T) {
	t0 := time.Date(1984, time.January, 1, 0, 0, 0, 0, time.UTC)

	type args struct {
		t time.Time
	}
	tests := []struct {
		name string
		seq  inflightSequence
		args args
		want time.Time
	}{
		{
			name: "empty case returns one minute wakeup",
			seq:  []*inFlightPacket{},
			args: args{t0},
			want: t0.Add(time.Minute),
		},
		{
			name: "single expired deadline returns ~now",
			seq: []*inFlightPacket{
				{deadline: t0.Add(-1 * time.Second)},
			},
			args: args{t0},
			want: t0.Add(time.Nanosecond),
		},
		{
			name: "a expired deadline returns ~now",
			seq: []*inFlightPacket{
				{deadline: t0.Add(-1 * time.Second)},
				{deadline: t0.Add(-2 * time.Second)},
				{deadline: t0.Add(10 * time.Millisecond)},
				{deadline: t0.Add(50 * time.Millisecond)},
			},
			args: args{t0},
			want: t0.Add(time.Nanosecond),
		},
		{
			name: "with several deadlines in the future, returns the lowest",
			seq: []*inFlightPacket{
				{deadline: t0.Add(10 * time.Millisecond)},
				{deadline: t0.Add(20 * time.Millisecond)},
				{deadline: t0.Add(50 * time.Millisecond)},
				{deadline: t0.Add(1 * time.Second)},
			},
			args: args{t0},
			want: t0.Add(10 * time.Millisecond),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.seq.nearestDeadlineTo(tt.args.t); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("inflightSequence.nearestDeadlineTo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_inflightSequence_readyToSend(t *testing.T) {
	t0 := time.Date(1984, time.January, 1, 0, 0, 0, 0, time.UTC)

	type args struct {
		t time.Time
	}
	tests := []struct {
		name string
		seq  inflightSequence
		args args
		want inflightSequence
	}{
		{
			name: "empty queue returns empty slice",
			seq:  []*inFlightPacket{},
			args: args{t0},
			want: []*inFlightPacket{},
		},
		{
			name: "not expired packet returns empty slice",
			seq: []*inFlightPacket{
				{deadline: t0.Add(10 * time.Millisecond)},
			},
			args: args{t0},
			want: []*inFlightPacket{},
		},
		{
			name: "one expired packet among many",
			seq: []*inFlightPacket{
				{
					packet:   &model.Packet{ID: 1},
					deadline: t0.Add(10 * time.Millisecond),
				},
				{
					packet:   &model.Packet{ID: 2},
					deadline: t0.Add(-1 * time.Millisecond),
				},
				{
					packet:   &model.Packet{ID: 3},
					deadline: t0.Add(20 * time.Millisecond),
				},
			},
			args: args{t0},
			want: []*inFlightPacket{
				{
					packet:   &model.Packet{ID: 2},
					deadline: t0.Add(-1 * time.Millisecond),
				},
			},
		},
		{
			name: "one expired packet and two fast retransmit",
			seq: []*inFlightPacket{
				{
					packet:   &model.Packet{ID: 1},
					deadline: t0.Add(10 * time.Millisecond),
				},
				{
					packet:   &model.Packet{ID: 2},
					deadline: t0.Add(-1 * time.Millisecond),
				},
				{
					packet:   &model.Packet{ID: 3},
					deadline: t0.Add(20 * time.Millisecond),
				},
				{
					packet:     &model.Packet{ID: 4},
					deadline:   t0.Add(100 * time.Millisecond),
					higherACKs: 3,
				},
				{
					packet:     &model.Packet{ID: 5},
					deadline:   t0.Add(100 * time.Millisecond),
					higherACKs: 5,
				},
			},
			args: args{t0},
			want: []*inFlightPacket{
				{
					packet:   &model.Packet{ID: 2},
					deadline: t0.Add(-1 * time.Millisecond),
				},
				{
					packet:     &model.Packet{ID: 4},
					deadline:   t0.Add(100 * time.Millisecond),
					higherACKs: 3,
				},
				{
					packet:     &model.Packet{ID: 5},
					deadline:   t0.Add(100 * time.Millisecond),
					higherACKs: 5,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.seq.readyToSend(tt.args.t); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("inflightSequence.readyToSend() = %v, want %v", got, tt.want)
			}
		})
	}
}
