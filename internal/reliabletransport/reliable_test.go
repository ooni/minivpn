package reliabletransport

import (
	"slices"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// test that we're able to reorder whatever is received.
func TestReliable_Reordering_withWorkers(t *testing.T) {
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
		inputSequence  []int
		outputSequence []int
	}
	getFields := func() fields {
		f := fields{
			DataOrControlToMuxer: func() *chan *model.Packet {
				ch := make(chan *model.Packet)
				return &ch
			}(),
			ControlToReliable: make(chan *model.Packet),
			MuxerToReliable:   make(chan *model.Packet),
			ReliableToControl: func() *chan *model.Packet {
				ch := make(chan *model.Packet)
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
			inputSequence:  []int{},
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
			name:   "test reordering for input sequence",
			fields: getFields(),
			args: func() args {
				args := getArgs()
				args.inputSequence = []int{3, 1, 2, 4}
				args.outputSequence = []int{1, 2, 3, 4}
				return args
			}(),
		},
		{
			name:   "test duplicates and reordering for input sequence",
			fields: getFields(),
			args: func() args {
				args := getArgs()
				args.inputSequence = []int{3, 3, 1, 1, 2, 4}
				args.outputSequence = []int{1, 2, 3, 4}
				return args
			}(),
		},
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

			sessionID := tt.args.sessionManager.LocalSessionID()
			dataIn := tt.fields.MuxerToReliable
			dataOut := tt.fields.ReliableToControl

			// create a buffered channel with "enough" capacity
			collectOut := make(chan *model.Packet, 1024)

			go func(chan *model.Packet) {
				for {
					pkt := <-*dataOut
					collectOut <- pkt
				}
			}(collectOut)

			for _, idx := range tt.args.inputSequence {
				dataIn <- &model.Packet{
					Opcode:          model.P_CONTROL_V1,
					RemoteSessionID: model.SessionID(sessionID),
					ID:              model.PacketID(idx),
				}
			}

			got := make([]int, 0)

			for i := 0; i < len(tt.args.outputSequence); i++ {
				pkt := <-collectOut
				got = append(got, int(pkt.ID))
			}

			if !slices.Equal(got, tt.args.outputSequence) {
				t.Errorf("Reordering: got = %v, want %v", got, tt.args.outputSequence)
			}
		})
	}
}
