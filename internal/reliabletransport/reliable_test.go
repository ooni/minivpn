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

	type fields struct {
		DataOrControlToMuxer *chan *model.Packet
		ControlToReliable    chan *model.Packet
		MuxerToReliable      chan *model.Packet
		ReliableToControl    *chan *model.Packet
	}
	type args struct {
		logger         model.Logger
		workersManager *workers.Manager
		sessionManager *session.Manager
		inputSequence  []string
		outputSequence []int
	}
	getFields := func() fields {
		f := fields{
			DataOrControlToMuxer: func() *chan *model.Packet {
				ch := make(chan *model.Packet)
				return &ch
			}(),
			ControlToReliable: make(chan *model.Packet),
			MuxerToReliable:   make(chan *model.Packet, 1024),
			ReliableToControl: func() *chan *model.Packet {
				ch := make(chan *model.Packet, 1024)
				return &ch
			}(),
		}
		return f
	}

	getArgs := func() args {
		a := args{
			logger:         log.Log,
			workersManager: workers.NewManager(log.Log),
			sessionManager: func() *session.Manager {
				m, _ := session.NewManager(log.Log)
				return m
			}(),
			inputSequence:  []string{},
			outputSequence: []int{},
		}
		return a
	}

	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "test proper ordering for input sequence",
			fields: getFields(),
			args: func() args {
				args := getArgs()
				args.inputSequence = []string{
					"[1] CONTROL_V1 +5ms",
					"[2] CONTROL_V1 +5ms",
					"[3] CONTROL_V1 +5ms",
					"[4] CONTROL_V1 +5ms",
				}
				args.outputSequence = []int{1, 2, 3, 4}
				return args
			}(),
		},

		// not yet! :)

		/*
			{
				name:   "test reordering for input sequence",
				fields: getFields(),
				args: func() args {
					args := getArgs()
					args.inputSequence = []string{
						"[2] CONTROL_V1 +5ms",
						"[4] CONTROL_V1 +5ms",
						"[3] CONTROL_V1 +5ms",
						"[1] CONTROL_V1 +5ms",
					}
					args.outputSequence = []int{1, 2, 3, 4}
					return args
				}(),
			},
		*/

		// TODO test duplicates
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				DataOrControlToMuxer: tt.fields.DataOrControlToMuxer,
				ControlToReliable:    tt.fields.ControlToReliable,
				MuxerToReliable:      tt.fields.MuxerToReliable,
				ReliableToControl:    tt.fields.ReliableToControl,
			}
			s.StartWorkers(tt.args.logger, tt.args.workersManager, tt.args.sessionManager)

			// the only two channels we're going to be testing on this test
			dataIn := tt.fields.MuxerToReliable
			dataOut := tt.fields.ReliableToControl
			sessionID := tt.args.sessionManager.LocalSessionID()

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, testStr := range tt.args.inputSequence {
					testPkt, err := vpntest.NewTestPacketFromString(testStr)
					if err != nil {
						t.Errorf("Reordering: error reading test sequence: %v", err.Error())
					}

					fmt.Printf("test packet: %v\n", testPkt)

					dataIn <- &model.Packet{
						Opcode:          testPkt.Opcode,
						RemoteSessionID: model.SessionID(sessionID),
						ID:              model.PacketID(testPkt.ID),
					}
					log.Debugf("sleeping for %T(%v)", testPkt.IAT, testPkt.IAT)
					time.Sleep(testPkt.IAT)
				}
				log.Info("test: done writing")
			}()

			wg.Wait()
			log.Debug("start collecting packets")

			got := make([]int, 0)

			for i := 0; i < len(tt.args.outputSequence); i++ {
				pkt := <-*dataOut
				got = append(got, int(pkt.ID))
				log.Debugf("got packet: %v", pkt.ID)
			}

			if !slices.Equal(got, tt.args.outputSequence) {
				t.Errorf("Reordering: got = %v, want %v", got, tt.args.outputSequence)
			}
		})
	}
}
