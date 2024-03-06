package reliabletransport

import (
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

// test that we can start and stop the workers
func TestService_StartWorkers(t *testing.T) {
	type fields struct {
		DataOrControlToMuxer *chan *model.Packet
		ControlToReliable    chan *model.Packet
		MuxerToReliable      chan *model.Packet
		ReliableToControl    *chan *model.Packet
	}
	type args struct {
		config         *config.Config
		workersManager *workers.Manager
		sessionManager *session.Manager
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "call startworkers with properly initialized channels",
			fields: fields{
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
			},
			args: args{
				config:         config.NewConfig(config.WithLogger(log.Log)),
				workersManager: workers.NewManager(log.Log),
				sessionManager: func() *session.Manager {
					m, _ := session.NewManager(config.NewConfig(config.WithLogger(log.Log)))
					return m
				}(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			s := &Service{
				DataOrControlToMuxer: tt.fields.DataOrControlToMuxer,
				ControlToReliable:    tt.fields.ControlToReliable,
				MuxerToReliable:      tt.fields.MuxerToReliable,
				ReliableToControl:    tt.fields.ReliableToControl,
			}
			s.StartWorkers(tt.args.config, tt.args.workersManager, tt.args.sessionManager)
			tt.args.workersManager.StartShutdown()
			tt.args.workersManager.WaitWorkersShutdown()
		})
	}
}
