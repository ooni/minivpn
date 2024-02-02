package reliabletransport

import (
	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

//
// Common utilities for tests in this package.
//

// initManagers initializes a workers manager and a session manager
func initManagers() (*workers.Manager, *session.Manager) {
	w := workers.NewManager(log.Log)
	s, err := session.NewManager(log.Log)
	if err != nil {
		panic(err)
	}
	return w, s
}
