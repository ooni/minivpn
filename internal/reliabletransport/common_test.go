package reliabletransport

import (
	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

//
// Common utilities for tests in this package.
//

// initManagers initializes a workers manager and a session manager.
func initManagers() (*workers.Manager, *session.Manager) {
	w := workers.NewManager(log.Log)
	s, err := session.NewManager(log.Log)
	if err != nil {
		panic(err)
	}
	return w, s
}

// newRandomSessionID returns a random session ID to initialize mock sessions.
func newRandomSessionID() model.SessionID {
	b, err := bytesx.GenRandomBytes(8)
	if err != nil {
		panic(err)
	}
	return model.SessionID(b)
}

func ackSetFromInts(s []int) *ackSet {
	acks := make([]model.PacketID, 0)
	for _, i := range s {
		acks = append(acks, model.PacketID(i))
	}
	return newACKSet(acks...)
}

func ackSetFromRange(start, total int) *ackSet {
	acks := make([]model.PacketID, 0)
	for i := 0; i < total; i++ {
		acks = append(acks, model.PacketID(start+i))
	}
	return newACKSet(acks...)
}
