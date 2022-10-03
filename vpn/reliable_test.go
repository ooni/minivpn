package vpn

import (
	"errors"
	"math"
	"testing"
)

func Test_reliableTransport_stop(t *testing.T) {
	stopCh := make(chan struct{}, 1)
	r := reliableTransport{
		stopChan: stopCh,
	}
	r.stop()
	if len(stopCh) != 1 {
		t.Errorf("expect len(stopChan) == 1")
	}
}

func Test_reliableTransport_processACK(t *testing.T) {
	type fields struct {
		waitingACKs map[packetID]chan<- struct{}
		acks        ackArray
	}

	w := make(map[packetID]chan<- struct{})
	r := &reliableTransport{
		waitingACKs: w,
	}

	payloadNilACK := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // sessionID
		0x00,                   // nACKs
		0x00, 0x00, 0x00, 0xff, // packetID
	}
	p := &packet{opcode: pControlV1, payload: payloadNilACK}
	r.processACK(p)
	if len(r.waitingACKs) != 0 {
		t.Error("expected 0 len waitingACKs")
	}

	payloadOneACK := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // local sessionID
		0x01,                  // nACKs
		0x00, 0x00, 0x00, 0x7, // ack packetID 7
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // remote sessionID
		0x00, 0x00, 0x00, 0xff, // packetID
	}
	toACK := packetID(0x07)
	r.waitingACKs[toACK] = make(chan struct{}, 1)
	p = &packet{opcode: pControlV1, payload: payloadOneACK}
	r.processACK(p)
	if len(r.waitingACKs) != 0 {
		t.Error("expected 0 len waitingACKs")
	}
}

func Test_reliableTransport_isPacketTooFar(t *testing.T) {
	type fields struct {
		receivingPID packetID
	}
	type args struct {
		p *packet
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "consecutive packets from zero return false",
			fields: fields{packetID(0)},
			args:   args{&packet{id: 1}},
			want:   false,
		},
		{
			name:   "consecutive packets from 1 returns false",
			fields: fields{packetID(1)},
			args:   args{&packet{id: 2}},
			want:   false,
		},
		{
			name:   "receiving=1, incoming=3 returns false",
			fields: fields{packetID(1)},
			args:   args{&packet{id: 3}},
			want:   false,
		},
		{
			name:   "out of the window returns true",
			fields: fields{packetID(1)},
			args:   args{&packet{id: 9}},
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableTransport{
				receivingPID: tt.fields.receivingPID,
			}
			if got := r.isPacketTooFar(tt.args.p); got != tt.want {
				t.Errorf("reliableTransport.isPacketTooFar() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reliableTransport_isDuplicatedPacket(t *testing.T) {
	type fields struct {
		receivedPackets [reliableRecvCacheSize]*packet
		receivingPID    packetID
	}
	type args struct {
		p *packet
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr error
	}{
		{
			name: "first packet is not duplicated when receivedPackets empty",
			fields: fields{
				receivedPackets: [8]*packet{},
				receivingPID:    packetID(0),
			},
			args:    args{&packet{id: packetID(1)}},
			want:    false,
			wantErr: nil,
		},
		{
			name: "packet ID 0 is duplicated",
			fields: fields{
				receivedPackets: [8]*packet{&packet{id: packetID(0)}},
				receivingPID:    packetID(0),
			},
			args:    args{&packet{id: packetID(0)}},
			want:    true,
			wantErr: nil,
		},
		{
			name: "packet ID 1 is duplicated when receivingPID == 1",
			fields: fields{
				receivedPackets: [8]*packet{&packet{id: packetID(1)}},
				receivingPID:    packetID(1),
			},
			args:    args{&packet{id: packetID(1)}},
			want:    true,
			wantErr: nil,
		},
		{
			name: "packet ID too far returns error",
			fields: fields{
				receivedPackets: [8]*packet{&packet{id: packetID(1)}},
				receivingPID:    packetID(1),
			},
			args:    args{&packet{id: packetID(12)}},
			want:    true,
			wantErr: errBadInput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reliableTransport{
				receivedPackets: tt.fields.receivedPackets,
				receivingPID:    tt.fields.receivingPID,
			}
			got, err := r.isDuplicatedPacket(tt.args.p)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("reliableTransport.isDuplicatedPacket() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("reliableTransport.isDuplicatedPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reliableTransport_queuePacketToSend(t *testing.T) {
	r := reliableTransport{
		ctrlSendChan: make(chan *outgoingPacket, 10),
	}
	if len(r.ctrlSendChan) != 0 {
		t.Error("expected ctrlSendChan of len 0")
	}
	r.queuePacketToSend(&outgoingPacket{})
	if len(r.ctrlSendChan) != 1 {
		t.Error("expected ctrlSendChan of len 1")
	}
	r.queuePacketToSend(&outgoingPacket{})
	r.queuePacketToSend(&outgoingPacket{})
	if len(r.ctrlSendChan) != 3 {
		t.Error("expected ctrlSendChan of len 3")
	}
	_ = <-r.ctrlSendChan
	_ = <-r.ctrlSendChan
	_ = <-r.ctrlSendChan
	if len(r.ctrlSendChan) != 0 {
		t.Error("expected ctrlSendChan of len 0")
	}
}

func Test_reliableTransport_UpdateLastACK(t *testing.T) {
	r := reliableTransport{}
	r.session = makeTestingSession()
	if r.session.lastACK != 0 {
		t.Error("expected session.lastACK == 0")
	}
	if err := r.UpdateLastACK(packetID(1)); err != nil {
		t.Error("packetID = 1, expected nil error")
	}
	if err := r.UpdateLastACK(packetID(10)); err != nil {
		t.Error("packetID = 10, expected nil error")
	}
	if r.session.lastACK != 10 {
		t.Error("expected session.lastACK == 10")
	}
	if err := r.UpdateLastACK(packetID(5)); err != errBadACK {
		t.Error("expected errBadACK")
	}
	tooHigh := math.MaxUint32
	r.session.lastACK = packetID(tooHigh)
	if err := r.UpdateLastACK(packetID(31416)); err != errExpiredKey {
		t.Error("expected errExpiredKey")
	}
}
