package tlsstate

import "github.com/ooni/minivpn/internal/model"

// Service is the tlsstate service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	NotifyTLS   chan *model.Notification
	TLSRecordUp chan []byte
}
