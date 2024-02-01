package reliabletransport

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/vpntest"
	"github.com/ooni/minivpn/internal/workers"
)

func initManagers() (*workers.Manager, *session.Manager) {
	w := workers.NewManager(log.Log)
	s, err := session.NewManager(log.Log)
	if err != nil {
		panic(err)
	}
	return w, s
}

// test that we're able to reorder (towards TLS) whatever is received (from the muxer).
func TestReliable_Reordering_withWorkers(t *testing.T) {

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
			name: "test proper ordering for input sequence",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			s := &Service{}

			// just to properly initialize it, we don't care about these
			s.ControlToReliable = make(chan *model.Packet)
			dataToMuxer := make(chan *model.Packet)
			s.DataOrControlToMuxer = &dataToMuxer

			// the only two channels we're going to be testing on this test
			dataIn := make(chan *model.Packet, 1024)
			dataOut := make(chan *model.Packet, 1024)

			s.MuxerToReliable = dataIn
			s.ReliableToControl = &dataOut

			workers, session := initManagers()
			sessionID := session.LocalSessionID()

			// let the workers pump up the jam!
			s.StartWorkers(log.Log, workers, session)

			for _, testStr := range tt.args.inputSequence {
				testPkt, err := vpntest.NewTestPacketFromString(testStr)
				if err != nil {
					t.Errorf("Reordering: error reading test sequence: %v", err.Error())
				}

				p := &model.Packet{
					Opcode:          testPkt.Opcode,
					RemoteSessionID: model.SessionID(sessionID),
					ID:              model.PacketID(testPkt.ID),
				}
				dataIn <- p
				time.Sleep(testPkt.IAT)
			}

			// start the result collector in a different goroutine
			var wg sync.WaitGroup
			wg.Add(1)
			go func(ch <-chan *model.Packet) {
				defer wg.Done()
				got := make([]int, 0)
				for {
					// have we read enough packets to call it a day?
					if len(got) >= len(tt.args.outputSequence) {
						break
					}
					// no, so let's keep reading until the test runner kills us
					pkt := <-ch
					got = append(got, int(pkt.ID))
					log.Debugf("got packet: %v", pkt.ID)
				}

				// let's check if what we got is correct
				if !slices.Equal(got, tt.args.outputSequence) {
					t.Errorf("Reordering: got = %v, want %v", got, tt.args.outputSequence)
				}
			}(dataOut)
			wg.Wait()
		})
	}
}
