package datachannel

import "github.com/ooni/minivpn/internal/model"

// Service is the datachannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	DataPacketUp chan *model.Packet
}
