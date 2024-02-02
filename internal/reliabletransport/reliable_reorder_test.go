package reliabletransport

import (
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/vpntest"
	"github.com/ooni/minivpn/internal/workers"
)

// initManagers initializes a workers manager and a session manager
func initManagers() (*workers.Manager, *session.Manager) {
	w := workers.NewManager(log.Log)
	s, err := session.NewManager(log.Log)
	if err != nil {
		panic(err)
	}
	return w, s
}

// test that we're able to reorder (towards TLS) whatever is received (from the muxer).
func TestReliable_Reordering_UP(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	type args struct {
		inputSequence  []string
		outputSequence []int
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "test with a well-ordered input sequence",
			args: args{
				inputSequence: []string{
					"[1] CONTROL_V1 +1ms",
					"[2] CONTROL_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
		{
			name: "test reordering for input sequence",
			args: args{
				inputSequence: []string{
					"[2] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[1] CONTROL_V1 +1ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
		{
			name: "test reordering for input sequence, longer waits",
			args: args{
				inputSequence: []string{
					"[2] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +10ms",
					"[3] CONTROL_V1 +1ms",
					"[1] CONTROL_V1 +50ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
		{
			name: "test reordering for input sequence, with duplicates",
			args: args{
				inputSequence: []string{
					"[2] CONTROL_V1 +1ms",
					"[2] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
					"[4] CONTROL_V1 +1ms",
					"[1] CONTROL_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[1] CONTROL_V1 +1ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
		{
			name: "reordering with acks interspersed",
			args: args{
				inputSequence: []string{
					"[2] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +2ms",
					"[0] ACK_V1 +1ms",
					"[3] CONTROL_V1 +1ms",
					"[0] ACK_V1 +1ms",
					"[1] CONTROL_V1 +2ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{}

			// just to properly initialize it, we don't care about these
			s.ControlToReliable = make(chan *model.Packet)
			dataToMuxer := make(chan *model.Packet)
			s.DataOrControlToMuxer = &dataToMuxer

			// the only two channels we're going to be testing on this test
			// we want to buffer enough to be safe writing to them.
			dataIn := make(chan *model.Packet, 1024)
			dataOut := make(chan *model.Packet, 1024)

			s.MuxerToReliable = dataIn
			s.ReliableToControl = &dataOut

			workers, session := initManagers()
			sessionID := session.LocalSessionID()

			t0 := time.Now()

			// let the workers pump up the jam!
			s.StartWorkers(log.Log, workers, session)

			writer := vpntest.NewPacketWriter(dataIn)
			writer.LocalSessionID = model.SessionID(sessionID)
			go writer.WriteSequence(tt.args.inputSequence)

			reader := vpntest.NewPacketReader(dataOut)
			if ok := reader.WaitForSequence(tt.args.outputSequence, t0); !ok {
				got := reader.Log().IDSequence()
				t.Errorf("Reordering: got = %v, want %v", got, tt.args.outputSequence)
			}
		})
	}
}
