package datachannel

import (
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// test that we can start and stop the workers
func TestService_StartWorkers(t *testing.T) {
	dataToMuxer := make(chan *model.Packet, 100)
	keyReady := make(chan *session.DataChannelKey)
	muxerToData := make(chan *model.Packet, 100)

	s := Service{
		MuxerToData:          muxerToData,
		DataOrControlToMuxer: &dataToMuxer,
		TUNToData:            make(chan []byte, 100),
		DataToTUN:            make(chan []byte, 100),
		KeyReady:             keyReady,
	}
	workers := workers.NewManager(log.Log)
	session := makeTestingSession()

	opts := makeTestingOptions(t, "AES-128-GCM", "sha512")
	s.StartWorkers(model.NewConfig(model.WithOpenVPNOptions(opts)), workers, session)

	keyReady <- makeTestingDataChannelKey()
	<-session.Ready
	muxerToData <- &model.Packet{Opcode: model.P_DATA_V1, Payload: []byte("aaa")}
	muxerToData <- &model.Packet{Opcode: model.P_DATA_V1, Payload: []byte("bbb")}
	workers.StartShutdown()
	workers.WaitWorkersShutdown()
}
