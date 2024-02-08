package reliabletransport

import (
	"slices"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/vpntest"
)

// test that everything that is received from below is eventually ACKed to the sender.
/*

   ┌────┐id ┌────┐
   │sndr│◄──┤rcvr│
   └─┬──┘   └──▲─┘
     │         │
     │         │
     │         │
     ▼       send
    ack
*/
func TestReliable_ACK(t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}

	type args struct {
		inputSequence []string
		start         int
		wantacks      int
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "ten ordered packets in",
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
				start:    1,
				wantacks: 10,
			},
		},
		{
			name: "five ordered packets with offset",
			args: args{
				inputSequence: []string{
					"[100] CONTROL_V1 +1ms",
					"[101] CONTROL_V1 +1ms",
					"[102] CONTROL_V1 +1ms",
					"[103] CONTROL_V1 +1ms",
					"[104] CONTROL_V1 +1ms",
				},
				start:    100,
				wantacks: 5,
			},
		},
		{
			name: "five reversed packets",
			args: args{
				inputSequence: []string{
					"[5] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[2] CONTROL_V1 +1ms",
					"[1] CONTROL_V1 +1ms",
				},
				start:    1,
				wantacks: 5,
			},
		},
		{
			name: "ten unordered packets with duplicates",
			args: args{
				inputSequence: []string{
					"[5] CONTROL_V1 +1ms",
					"[1] CONTROL_V1 +1ms",
					"[5] CONTROL_V1 +1ms",
					"[2] CONTROL_V1 +1ms",
					"[1] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
					"[2] CONTROL_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
				},
				start:    1,
				wantacks: 5,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{}

			// just to properly initialize it, we don't care about these
			s.ControlToReliable = make(chan *model.Packet)
			// this one up to control/tls also needs to be buffered because otherwise
			// we'll block on the receiver when delivering up.
			reliableToControl := make(chan *model.Packet, 1024)
			s.ReliableToControl = &reliableToControl

			// the only two channels we're going to be testing on this test
			// we want to buffer enough to be safe writing to them.
			dataIn := make(chan *model.Packet, 1024)
			dataOut := make(chan *model.Packet, 1024)

			s.MuxerToReliable = dataIn        // up
			s.DataOrControlToMuxer = &dataOut // down

			workers, session := initManagers()

			t0 := time.Now()

			// let the workers pump up the jam!
			s.StartWorkers(model.NewConfig(model.WithLogger(log.Log)), workers, session)

			writer := vpntest.NewPacketWriter(dataIn)

			// initialize a mock session ID for our peer
			initializeSessionIDForWriter(writer, session)

			go writer.WriteSequence(tt.args.inputSequence)

			reader := vpntest.NewPacketReader(dataOut)
			witness := vpntest.NewWitness(reader)

			if ok := witness.VerifyNumberOfACKs(tt.args.wantacks, t0); !ok {
				got := len(witness.Log().ACKs())
				t.Errorf("TestACK: got = %v, want %v", got, tt.args.wantacks)
			}
			gotAckSet := ackSetFromInts(witness.Log().ACKs()).sorted()
			wantAckSet := ackSetFromRange(tt.args.start, tt.args.wantacks).sorted()

			if !slices.Equal(gotAckSet, wantAckSet) {
				t.Errorf("TestACK: got = %v, want %v", gotAckSet, wantAckSet)

			}
		})
	}
}
