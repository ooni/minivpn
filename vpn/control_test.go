package vpn

import (
	"bytes"
	"errors"
	"math"
	"net"
	"reflect"
	"testing"
)

func Test_newSession(t *testing.T) {
	tests := []struct {
		name    string
		want    *session
		wantErr bool
	}{
		{"get session", &session{}, false},
	}
	// TODO(ainghazal): get smarter and use test values (turn sesion into an interface).
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newSession()
			if (err != nil) != tt.wantErr {
				t.Errorf("newSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_maybeAddSizeFrame(t *testing.T) {

	type args struct {
		conn    net.Conn
		payload []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{

		// FIXME ---- fix these tests ---
		/*
			{
				name: "udp",
				args: args{
					makeTestinConnFromNetwork("udp"),
					[]byte{0xff, 0xfe, 0xfd},
				},
				want: []byte{0xff, 0xfe, 0xfd},
			},
			{
				name: "tcp",
				args: args{
					makeTestinConnFromNetwork("udp"),
					[]byte{0xff, 0xfe, 0xfd},
				},
				want: []byte{0x00, 0x03, 0xff, 0xfe, 0xfd},
			},
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maybeAddSizeFrame(tt.args.conn, tt.args.payload); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maybeAddSizeFrame() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_session_ActiveKey(t *testing.T) {
	s := &session{
		keys:  make([]*dataChannelKey, 2),
		keyID: 10,
	}
	_, err := s.ActiveKey()
	wantErr := errDataChannelKey
	if !errors.Is(err, wantErr) {
		t.Errorf("session.ActiveKey() = got err %v, want %v", err, wantErr)
	}
}

func Test_session_LocalPacketID(t *testing.T) {
	type fields struct {
		RemoteSessionID sessionID
		LocalSessionID  sessionID
		keys            []*dataChannelKey
		keyID           int
		localPacketID   packetID
		lastACK         packetID
	}

	tests := []struct {
		name    string
		fields  fields
		want    packetID
		wantErr error
	}{
		{
			"return arbitrary value",
			fields{localPacketID: packetID(42)},
			packetID(42),
			nil,
		},
		{
			"return zero",
			fields{localPacketID: packetID(0)},
			packetID(0),
			nil,
		},
		{
			"overflow",
			fields{localPacketID: math.MaxUint32},
			packetID(0),
			errExpiredKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &session{
				localPacketID: tt.fields.localPacketID,
			}
			if got, err := s.LocalPacketID(); got != tt.want || err != tt.wantErr {
				t.Errorf("session.LocalPacketID() = %v, want %v", got, tt.want)
			}
		})
	}

	// increments
	val := packetID(1000)
	s := &session{localPacketID: packetID(1000)}

	if got, _ := s.LocalPacketID(); got != val {
		t.Errorf("session.LocalPacketID() = %v, want %v", got, val)
	}
	val++
	if got, _ := s.LocalPacketID(); got != val {
		t.Errorf("session.LocalPacketID() = %v, want %v", got, val)
	}
	val++
	if got, _ := s.LocalPacketID(); got != val {
		t.Errorf("session.LocalPacketID() = %v, want %v", got, val)
	}
}

/*
 func Test_session_isNextPacket(t *testing.T) {
 	type fields struct {
 		lastACK packetID
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
 			"is next",
 			fields{lastACK: packetID(0)},
 			args{&packet{id: packetID(1)}},
 			true,
 		},
 		{
 			"is two more",
 			fields{lastACK: packetID(0)},
 			args{&packet{id: packetID(2)}},
 			false,
 		},
 		{
 			"is lesser",
 			fields{lastACK: packetID(100)},
 			args{&packet{id: packetID(99)}},
 			false,
 		},
 		{
 			"is nil",
 			fields{lastACK: packetID(100)},
 			args{nil},
 			false,
 		},
 	}
 	for _, tt := range tests {
 		t.Run(tt.name, func(t *testing.T) {
 			s := &session{
 				lastACK: tt.fields.lastACK,
 			}
 			if got := s.isNextPacket(tt.args.p); got != tt.want {
 				t.Errorf("session.isNextPacket() = %v, want %v", got, tt.want)
 			}
 		})
 	}
 }
*/

func Test_isBadAuthReply(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"bad_auth", args{[]byte("AUTH_FAILED")}, true},
		{"too_large", args{[]byte("AUTH_FAILEDAAAAAA")}, true},
		{"too_short", args{[]byte("AAA")}, false},
		{"empty", args{[]byte("")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBadAuthReply(tt.args.b); got != tt.want {
				t.Errorf("isBadAuthReply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isPushReply(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"push_reply", args{serverPushReply}, true},
		{"too_large", args{[]byte("PUSH_REPLYAAA")}, true},
		{"too_short", args{[]byte("AAA")}, false},
		{"empty", args{[]byte("")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPushReply(tt.args.b); got != tt.want {
				t.Errorf("isPushReply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isControlMessage(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"good_control", args{controlMessageHeader}, true},
		{"bad_control", args{[]byte{0x00, 0x00, 0x00, 0x01}}, false},
		{"too_short", args{[]byte{0x00}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isControlMessage(tt.args.b); got != tt.want {
				t.Errorf("isControlMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_control_PushRequest(t *testing.T) {
	c := &control{}
	got := c.PushRequest()
	if !bytes.Equal(got[:len(got)-1], []byte("PUSH_REQUEST")) {
		t.Errorf("control_PushRequest() = %v", got)
	}
	if got[len(got)-1] != 0x00 {
		t.Errorf("control_PushRequest(): expected trailing null byte")
	}
}
