package vpn

import (
	"math"
	"net"
	"reflect"
	"testing"
)

// TODO test muxer instead
/*
func Test_newControl(t *testing.T) {
	rnd := "0123456789"

	conn, _ := net.Dial("tcp", "127.0.0.1:0")
	ks := &keySource{[]byte(rnd), []byte(rnd), []byte(rnd)}
	o := &Options{}

	ctrl := control{}
	if ctrl == nil {
		t.Fatalf("ctrl should not be nil")
	}
	err := ctrl.initSession()
	if err != nil {
		t.Fatalf("initSession should not fail")
	}
	if len(ctrl.SessionID) == 0 {
		t.Fatalf("Local session should be initialized")
	}
}
*/

//var sID sessionID
//copy(sID[:], []byte{0xde, 0xad, 0xbe, 0xef})

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
	connUDP, _ := net.Dial("udp", "127.0.0.1:0")
	// whatever is not UDP we consider to be TCP.
	// TODO can we get a TCP conn?
	_, conn := net.Pipe()

	type args struct {
		conn    net.Conn
		payload []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"udp", args{connUDP, []byte{0xff, 0xfe, 0xfd}}, []byte{0xff, 0xfe, 0xfd}},
		{"tcp", args{conn, []byte{0xff, 0xfe, 0xfd}}, []byte{0x00, 0x03, 0xff, 0xfe, 0xfd}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maybeAddSizeFrame(tt.args.conn, tt.args.payload); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maybeAddSizeFrame() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_session_LocalPacketID(t *testing.T) {
	type fields struct {
		RemoteSessionID sessionID
		LocalSessionID  sessionID
		keys            []*dataChannelKey
		keyID           int
		localPacketID   uint32
		lastACK         uint32
		ackQueue        chan *packet
	}

	tests := []struct {
		name    string
		fields  fields
		want    uint32
		wantErr error
	}{
		{
			"return arbitrary value",
			fields{localPacketID: uint32(42)},
			uint32(42),
			nil,
		},
		{
			"return zero",
			fields{localPacketID: uint32(0)},
			uint32(0),
			nil,
		},
		{
			"overflow",
			fields{localPacketID: math.MaxUint32},
			uint32(0),
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
	val := uint32(1000)
	s := &session{localPacketID: uint32(1000)}

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

func Test_session_isNextPacket(t *testing.T) {
	type fields struct {
		lastACK uint32
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
			fields{lastACK: uint32(0)},
			args{&packet{id: 1}},
			true,
		},
		{
			"is two more",
			fields{lastACK: uint32(0)},
			args{&packet{id: 2}},
			false,
		},
		{
			"is lesser",
			fields{lastACK: uint32(100)},
			args{&packet{id: 99}},
			false,
		},
		{
			"is nil",
			fields{lastACK: uint32(100)},
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
