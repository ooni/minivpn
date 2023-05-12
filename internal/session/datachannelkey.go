package session

import (
	"errors"
	"fmt"
	"sync"
)

// DataChannelKey represents a pair of key sources that have been negotiated
// over the control channel, and from which we will derive local and remote
// keys for encryption and decrption over the data channel. The index refers to
// the short key_id that is passed in the lower 3 bits if a packet header.
// The setup of the keys for a given data channel (that is, for every key_id)
// is made by expanding the keysources using the prf function.
// Do note that we are not yet implementing key renegotiation - but the index
// is provided for convenience when/if we support that in the future.
type DataChannelKey struct {
	index  uint32
	ready  bool
	local  *KeySource
	remote *KeySource
	mu     sync.Mutex
}

// errDayaChannelKey is a [DataChannelKey] error.
var errDataChannelKey = errors.New("bad data-channel key")

// AddRemoteKey adds the server keySource to our dataChannelKey. This makes the
// dataChannelKey ready to be used.
func (dck *DataChannelKey) AddRemoteKey(k *KeySource) error {
	dck.mu.Lock()
	defer dck.mu.Unlock()
	if dck.ready {
		return fmt.Errorf("%w:%s", errDataChannelKey, "cannot overwrite remote key slot")
	}
	dck.remote = k
	dck.ready = true
	return nil
}

// Ready returns whether the [DataChannelKey] is ready.
func (dck *DataChannelKey) Ready() bool {
	dck.mu.Lock()
	defer dck.mu.Unlock()
	return dck.ready
}
