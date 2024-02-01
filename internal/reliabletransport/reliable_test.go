package reliabletransport

import (
	"fmt"
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
					"[1] CONTROL_V1 +5ms",
					"[2] CONTROL_V1 +5ms",
					"[3] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +5ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
		{
			name: "test reordering for input sequence",
			args: args{
				inputSequence: []string{
					"[2] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +5ms",
					"[3] CONTROL_V1 +5ms",
					"[1] CONTROL_V1 +5ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
		{
			name: "test reordering for input sequence, longer waits",
			args: args{
				inputSequence: []string{
					"[2] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +50ms",
					"[3] CONTROL_V1 +100ms",
					"[1] CONTROL_V1 +100ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
		{
			name: "test reordering for input sequence, with duplicates",
			args: args{
				inputSequence: []string{
					"[2] CONTROL_V1 +5ms",
					"[2] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +5ms",
					"[1] CONTROL_V1 +5ms",
					"[3] CONTROL_V1 +5ms",
					"[1] CONTROL_V1 +5ms",
				},
				outputSequence: []int{1, 2, 3, 4},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataToMuxer := make(chan *model.Packet)

			// the only two channels we're going to be testing on this test
			dataIn := make(chan *model.Packet, 1024)
			dataOut := make(chan *model.Packet, 1024)

			workersManager := workers.NewManager(log.Log)
			sessionManager, err := session.NewManager(log.Log)
			if err != nil {
				t.Errorf("Reordering: cannot create session.Manager: %v", err.Error())
			}

			s := &Service{
				DataOrControlToMuxer: nil,
				ControlToReliable:    make(chan *model.Packet),
				MuxerToReliable:      dataIn,
				ReliableToControl:    nil,
			}
			s.DataOrControlToMuxer = &dataToMuxer
			s.ReliableToControl = &dataOut
			sessionID := sessionManager.LocalSessionID()

			// let the workers pump up the jam!
			s.StartWorkers(log.Log, workersManager, sessionManager)

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
						fmt.Println("we got enough packets!", got)
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
