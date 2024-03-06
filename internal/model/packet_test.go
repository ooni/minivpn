package model

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewOpcodeFromString(t *testing.T) {
	tests := []struct {
		name    string
		str     string
		want    Opcode
		wantErr bool
	}{
		{
			name:    "hard reset client v1",
			str:     "CONTROL_HARD_RESET_CLIENT_V1",
			want:    P_CONTROL_HARD_RESET_CLIENT_V1,
			wantErr: false,
		},
		{
			name:    "control hard reset server v1",
			str:     "CONTROL_HARD_RESET_SERVER_V1",
			want:    P_CONTROL_HARD_RESET_SERVER_V1,
			wantErr: false,
		},
		{
			name:    "control hard reset client v2",
			str:     "CONTROL_HARD_RESET_CLIENT_V2",
			want:    P_CONTROL_HARD_RESET_CLIENT_V2,
			wantErr: false,
		},
		{
			name:    "control hard reset server v2",
			str:     "CONTROL_HARD_RESET_SERVER_V2",
			want:    P_CONTROL_HARD_RESET_SERVER_V2,
			wantErr: false,
		},
		{
			name:    "soft reset v1",
			str:     "CONTROL_SOFT_RESET_V1",
			want:    P_CONTROL_SOFT_RESET_V1,
			wantErr: false,
		},
		{
			name:    "control v1",
			str:     "CONTROL_V1",
			want:    P_CONTROL_V1,
			wantErr: false,
		},
		{
			name:    "ack v1",
			str:     "ACK_V1",
			want:    P_ACK_V1,
			wantErr: false,
		},
		{
			name:    "data v1",
			str:     "DATA_V1",
			want:    P_DATA_V1,
			wantErr: false,
		},
		{
			name:    "data v2",
			str:     "DATA_V2",
			want:    P_DATA_V2,
			wantErr: false,
		},
		{
			name:    "wrong",
			str:     "UNKNOWN",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty",
			str:     "",
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewOpcodeFromString(tt.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOpcodeFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NewOpcodeFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpcode_String(t *testing.T) {
	t.Run("known opcode to string should not fail", func(t *testing.T) {
		opcodes := map[Opcode]string{
			P_CONTROL_HARD_RESET_CLIENT_V1: "P_CONTROL_HARD_RESET_CLIENT_V1",
			P_CONTROL_HARD_RESET_SERVER_V1: "P_CONTROL_HARD_RESET_SERVER_V1",
			P_CONTROL_SOFT_RESET_V1:        "P_CONTROL_SOFT_RESET_V1",
			P_CONTROL_V1:                   "P_CONTROL_V1",
			P_ACK_V1:                       "P_ACK_V1",
			P_DATA_V1:                      "P_DATA_V1",
			P_CONTROL_HARD_RESET_CLIENT_V2: "P_CONTROL_HARD_RESET_CLIENT_V2",
			P_CONTROL_HARD_RESET_SERVER_V2: "P_CONTROL_HARD_RESET_SERVER_V2",
			P_DATA_V2:                      "P_DATA_V2",
		}
		for k, v := range opcodes {
			if v != k.String() {
				t.Errorf("bad opcode string: %s", k.String())
			}

		}
	})
	t.Run("unknown opcode representation", func(t *testing.T) {
		got := Opcode(20).String()
		if got != "P_UNKNOWN" {
			t.Errorf("expected unknown opcode as P_UNKNOWN, got %s", got)
		}
	})
}

func Test_NewPacket(t *testing.T) {
	type args struct {
		opcode  Opcode
		keyID   byte
		payload []byte
	}
	tests := []struct {
		name string
		args args
		want *Packet
	}{
		{
			name: "get packet ok",
			args: args{
				opcode:  Opcode(1),
				keyID:   byte(10),
				payload: []byte("not a payload"),
			},
			want: &Packet{
				Opcode:  Opcode(1),
				KeyID:   byte(10),
				ACKs:    []PacketID{},
				Payload: []byte("not a payload"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(NewPacket(tt.args.opcode, tt.args.keyID, tt.args.payload), tt.want); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func Test_ParsePacket(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    *Packet
		wantErr error
	}{
		{
			name:    "a single byte cannot be parsed as a packet",
			raw:     "20",
			want:    nil,
			wantErr: ErrPacketTooShort,
		},
		{
			name: "parse minimal control packet",
			raw:  "2000000000000000000000000007",
			want: &Packet{
				ID:      7,
				Opcode:  P_CONTROL_V1,
				KeyID:   0,
				ACKs:    []PacketID{},
				Payload: []byte{},
			},
			wantErr: nil,
		},
		{
			name: "parse control packet with payload",
			raw:  "2000000000000000000000000007616161",
			want: &Packet{
				ID:      7,
				Opcode:  P_CONTROL_V1,
				KeyID:   0,
				ACKs:    []PacketID{},
				Payload: []byte("aaa"),
			},
			wantErr: nil,
		},
		{
			name:    "parse control packet with incomplete session id",
			raw:     "2000",
			want:    nil,
			wantErr: ErrParsePacket,
		},
		{
			name: "parse data packet",
			raw:  "48020202ffff",
			want: &Packet{
				ID:      0,
				Opcode:  P_DATA_V2,
				KeyID:   0,
				PeerID:  PeerID{0x02, 0x02, 0x02},
				ACKs:    []PacketID{},
				Payload: []byte{0xff, 0xff},
			},
			wantErr: nil,
		},
		{
			name:    "parse data fails if too short",
			raw:     "4802020",
			want:    &Packet{},
			wantErr: ErrPacketTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(tt.raw)
			p, err := ParsePacket(raw)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got error=%v, want %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(p, tt.want); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func Test_Packet_Bytes(t *testing.T) {
	t.Run("serialize a bare mininum packet", func(t *testing.T) {
		p := &Packet{Opcode: P_ACK_V1}
		got, err := p.Bytes()
		if err != nil {
			t.Error("should not fail")
		}
		want := []byte{40, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf(diff)
		}
	})

	t.Run("a packet with too many acks should fail", func(t *testing.T) {
		id := PacketID(1)
		tooManyAcks := []PacketID{
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		}

		p := &Packet{
			Opcode: P_ACK_V1,
			ACKs:   tooManyAcks,
		}
		_, err := p.Bytes()
		if !errors.Is(err, ErrMarshalPacket) {
			t.Errorf("expected got error=%v, expected %v", err, ErrMarshalPacket)
		}
	})
}

func Test_Packet_IsControl(t *testing.T) {
	type fields struct {
		opcode Opcode
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "good control",
			fields: fields{opcode: Opcode(P_CONTROL_V1)},
			want:   true,
		},
		{
			name:   "data v1 packet",
			fields: fields{opcode: Opcode(P_DATA_V1)},
			want:   false,
		},
		{
			name:   "data v2 packet",
			fields: fields{opcode: Opcode(P_DATA_V2)},
			want:   false,
		},
		{
			name:   "zero byte",
			fields: fields{opcode: 0x00},
			want:   false,
		},
		{
			name:   "ack",
			fields: fields{opcode: Opcode(P_ACK_V1)},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{Opcode: tt.fields.opcode}
			if got := p.IsControl(); got != tt.want {
				t.Errorf("packet.IsControl() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Packet_IsData(t *testing.T) {
	type fields struct {
		opcode Opcode
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "data v1 is true",
			fields: fields{opcode: Opcode(P_DATA_V1)},
			want:   true,
		},
		{
			name:   "data v2 is true",
			fields: fields{opcode: Opcode(P_DATA_V2)},
			want:   true,
		},
		{
			name:   "control packet",
			fields: fields{opcode: Opcode(P_CONTROL_V1)},
			want:   false,
		},
		{
			name:   "ack",
			fields: fields{opcode: Opcode(P_ACK_V1)},
			want:   false,
		},
		{
			name:   "zero byte",
			fields: fields{opcode: 0x00},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{Opcode: tt.fields.opcode}
			if got := p.IsData(); got != tt.want {
				t.Errorf("packet.IsData() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Regression test for MIV-01-001
func Test_Crash_WhileParsingServerHardResetPacket(t *testing.T) {
	packet := NewPacket(
		P_CONTROL_HARD_RESET_SERVER_V2,
		0,
		[]byte{},
	)
	b, _ := packet.Bytes()
	ParsePacket(b)
}

func Test_Packet_Log(t *testing.T) {
	t.Run("log control packet outgoing", func(t *testing.T) {
		p := NewPacket(P_CONTROL_V1, 0, []byte("aaa"))
		p.ID = 42
		p.ACKs = []PacketID{1}
		logger := NewTestLogger()
		p.Log(logger, DirectionOutgoing)
		want := "> P_CONTROL_V1 {id=42, acks=[1]} localID=0000000000000000 remoteID=0000000000000000 [3 bytes]"
		got := logger.Lines[0]
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf(diff)
		}
	})
	t.Run("log data packet incoming", func(t *testing.T) {
		p := NewPacket(P_DATA_V1, 0, []byte("aaa"))
		p.ID = 42
		p.ACKs = []PacketID{2}
		logger := NewTestLogger()
		p.Log(logger, DirectionIncoming)
		want := "< P_DATA_V1 {id=42, acks=[2]} localID=0000000000000000 remoteID=0000000000000000 [3 bytes]"
		got := logger.Lines[0]
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf(diff)
		}
	})
}
