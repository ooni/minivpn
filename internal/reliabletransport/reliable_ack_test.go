package reliabletransport

import (
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/vpntest"
)

// test that everything that is received from below is eventually ACKed to the sender.
func TestReliable_ACK(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	type args struct {
		inputSequence []string
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
				wantacks: 10,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{}

			// just to properly initialize it, we don't care about these
			s.ControlToReliable = make(chan *model.Packet)
			reliableToControl := make(chan *model.Packet)
			s.ReliableToControl = &reliableToControl

			// the only two channels we're going to be testing on this test
			// we want to buffer enough to be safe writing to them.
			dataIn := make(chan *model.Packet, 1024)
			dataOut := make(chan *model.Packet, 1024)

			s.MuxerToReliable = dataIn        // up
			s.DataOrControlToMuxer = &dataOut // down

			workers, session := initManagers()

			// this is our session (local to us)
			localSessionID := session.LocalSessionID()
			remoteSessionID := session.RemoteSessionID()

			t0 := time.Now()

			// let the workers pump up the jam!
			s.StartWorkers(log.Log, workers, session)

			writer := vpntest.NewPacketWriter(dataIn)

			// TODO -- need to create a session
			writer.LocalSessionID = model.SessionID(remoteSessionID)
			writer.RemoteSessionID = model.SessionID(localSessionID)

			go writer.WriteSequence(tt.args.inputSequence)

			reader := vpntest.NewPacketReader(dataOut)
			witness := vpntest.NewWitness(reader)

			if ok := witness.VerifyACKs(tt.args.wantacks, t0); !ok {
				//log.Debug(witness.Log())
				got := witness.NumberOfACKs()
				t.Errorf("Reordering: got = %v, want %v", got, tt.args.wantacks)
			}
		})
	}
}
