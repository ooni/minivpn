package reliabletransport

import (
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/vpntest"
)

// test that everything that is sent eventually arrives in bounded time, in the pressence of losses.
/*
        |
	   v
    ┌────┐ack┌────┐
    │sndr│◄──┤rcvr│
    └─┬──┘   └──▲─┘
      │         │
drop◄─┤         │
      │         │
      ▼relay (ack)

*/
func TestReliable_WithLoss(t *testing.T) {

	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}

	type args struct {
		inputSequence []string
		inputPayload  string
		want          string
		losses        []int
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "ten ordered packets with no loss",
			args: args{
				inputSequence: []string{
					"[1] CONTROL_V1 +1ms",
					"[2] CONTROL_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
					"[5] CONTROL_V1 +1ms",
					"[6] CONTROL_V1 +1ms",
					"[7] CONTROL_V1 +1ms",
					"[8] CONTROL_V1 +1ms",
					"[9] CONTROL_V1 +1ms",
					"[10] CONTROL_V1 +1ms",
				},
				inputPayload: "aaabbbcccdddeeefffggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{},
			},
		},
		{
			name: "ten ordered packets, first loss",
			args: args{
				inputSequence: []string{
					"[1] CONTROL_V1 +10ms",
					"[2] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +10ms",
					"[4] CONTROL_V1 +10ms",
					"[5] CONTROL_V1 +10ms",
					"[6] CONTROL_V1 +10ms",
					"[7] CONTROL_V1 +10ms",
					"[8] CONTROL_V1 +10ms",
					"[9] CONTROL_V1 +10ms",
					"[10] CONTROL_V1 +10ms",
				},
				inputPayload: "aaabbbcccdddeeefffggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{1},
			},
		},
		{
			name: "ten ordered packets, 1,3,5,7 loss",
			args: args{
				inputSequence: []string{
					"[1] CONTROL_V1 +10ms",
					"[2] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +10ms",
					"[4] CONTROL_V1 +10ms",
					"[5] CONTROL_V1 +10ms",
					"[6] CONTROL_V1 +10ms",
					"[7] CONTROL_V1 +10ms",
					"[8] CONTROL_V1 +10ms",
					"[9] CONTROL_V1 +10ms",
					"[10] CONTROL_V1 +10ms",
				},
				inputPayload: "aaabbbcccdddeeefffggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{1, 3, 5, 7},
			},
		},
		{
			name: "ten ordered packets, 2,4,6,8 loss",
			args: args{
				inputSequence: []string{
					"[1] CONTROL_V1 +10ms",
					"[2] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +10ms",
					"[4] CONTROL_V1 +10ms",
					"[5] CONTROL_V1 +10ms",
					"[6] CONTROL_V1 +10ms",
					"[7] CONTROL_V1 +10ms",
					"[8] CONTROL_V1 +10ms",
					"[9] CONTROL_V1 +10ms",
					"[10] CONTROL_V1 +10ms",
				},
				inputPayload: "aaabbbcccdddeeefffggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{2, 4, 6, 8},
			},
		},
		{
			name: "ten ordered packets, 2-5 loss, 2 lost again",
			args: args{
				inputSequence: []string{
					"[1] CONTROL_V1 +10ms",
					"[2] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +10ms",
					"[4] CONTROL_V1 +10ms",
					"[5] CONTROL_V1 +10ms",
					"[6] CONTROL_V1 +10ms",
					"[7] CONTROL_V1 +10ms",
					"[8] CONTROL_V1 +10ms",
					"[9] CONTROL_V1 +10ms",
					"[10] CONTROL_V1 +10ms",
				},
				inputPayload: "aaabbbcccdddeeefffggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{2, 3, 4, 5, 2},
			},
		},
		{
			name: "ten out-of-order packets",
			args: args{
				inputSequence: []string{
					"[6] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +10ms",
					"[1] CONTROL_V1 +10ms",
					"[2] CONTROL_V1 +10ms",
					"[4] CONTROL_V1 +10ms",
					"[5] CONTROL_V1 +10ms",
					"[7] CONTROL_V1 +10ms",
					"[8] CONTROL_V1 +10ms",
					"[9] CONTROL_V1 +10ms",
					"[10] CONTROL_V1 +10ms",
				},
				inputPayload: "fffcccaaabbbdddeeeggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{},
			},
		},
		{
			name: "ten out-of-order packets, loss=1,5",
			args: args{
				inputSequence: []string{
					"[6] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +10ms",
					"[1] CONTROL_V1 +10ms",
					"[2] CONTROL_V1 +10ms",
					"[4] CONTROL_V1 +10ms",
					"[5] CONTROL_V1 +10ms",
					"[7] CONTROL_V1 +10ms",
					"[8] CONTROL_V1 +10ms",
					"[9] CONTROL_V1 +10ms",
					"[10] CONTROL_V1 +10ms",
				},
				inputPayload: "fffcccaaabbbdddeeeggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{1, 5},
			},
		},
		{
			name: "ten ordered packets, first lost 4 times",
			args: args{
				inputSequence: []string{
					"[1] CONTROL_V1 +10ms",
					"[2] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +10ms",
					"[4] CONTROL_V1 +10ms",
					"[5] CONTROL_V1 +10ms",
					"[6] CONTROL_V1 +10ms",
					"[7] CONTROL_V1 +10ms",
					"[8] CONTROL_V1 +10ms",
					"[9] CONTROL_V1 +10ms",
					"[10] CONTROL_V1 +10ms",
				},
				inputPayload: "aaabbbcccdddeeefffggghhhiiijjj",
				want:         "aaabbbcccdddeeefffggghhhiiijjj",
				losses:       []int{1, 1, 1, 1},
			},
		},
		{
			name: "arbitrary text",
			args: args{
				inputSequence: []string{"[1..150] CONTROL_V1 +10ms"},
				inputPayload:  "I think that the next two generations of Americans will be grappling with the very real specter of finding themselves living in a new and bizarre kind of digital totalitarian state - one that looks and feels democratic on the surface, but has a fierce undercurrent of fear and technologically enforced fascism any time you step out of line. I really hope this isn't the case, but it looks really bad right now, doesn't it?",
				want:          "I think that the next two generations of Americans will be grappling with the very real specter of finding themselves living in a new and bizarre kind of digital totalitarian state - one that looks and feels democratic on the surface, but has a fierce undercurrent of fear and technologically enforced fascism any time you step out of line. I really hope this isn't the case, but it looks really bad right now, doesn't it?",
				losses:        []int{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{}

			// where we write stuff
			dataIn := make(chan *model.Packet, 1024)

			// where we want to read reordered stuff
			dataOut := make(chan *model.Packet, 1024)

			s.ControlToReliable = dataIn
			// this one up to control/tls also needs to be buffered because otherwise
			// we'll block on the receiver when delivering up.
			reliableToControl := dataOut
			s.ReliableToControl = &reliableToControl

			// data out from reliable
			toMuxer := make(chan *model.Packet, 1024)
			s.DataOrControlToMuxer = &toMuxer // down

			// this will be the data out after losses
			toNetwork := make(chan *model.Packet, 1024)

			// data in from network
			fromMuxer := make(chan *model.Packet, 1024)
			s.MuxerToReliable = fromMuxer // up

			workers, session := initManagers()

			t0 := time.Now()

			// let the workers pump up the jam!
			s.StartWorkers(log.Log, workers, session)

			writer := vpntest.NewPacketWriter(dataIn)

			// initialize a mock session ID for our peer
			peerSessionID := newRandomSessionID()

			session.SetRemoteSessionID(peerSessionID)

			go writer.WriteSequenceWithFixedPayload(tt.args.inputSequence, tt.args.inputPayload, 3)

			reader := vpntest.NewPacketReader(dataOut)
			witness := vpntest.NewWitness(reader)

			// start a relay to simulate losses
			relay := vpntest.NewPacketRelay(toMuxer, toNetwork)
			go relay.RelayWithLosses(tt.args.losses)
			defer relay.Stop()

			// start a mock server that echoes payloads with sequenced packets and acks
			echoServer := vpntest.NewEchoServer(toNetwork, fromMuxer)
			echoServer.RemoteSessionID = model.SessionID(session.LocalSessionID())
			go echoServer.Start()
			defer echoServer.Stop()

			if ok := witness.VerifyOrderedPayload(tt.args.want, t0); !ok {
				t.Errorf("TestLoss: payload does not match. got=%s, want=%s", witness.Payload(), tt.args.want)
			}
		})
	}
}
