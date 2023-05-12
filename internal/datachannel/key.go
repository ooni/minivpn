package datachannel

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/ooni/minivpn/internal/bytesx"
)

var randomFn = bytesx.GenRandomBytes

// dataChannelKey represents a pair of key sources that have been negotiated
// over the control channel, and from which we will derive local and remote
// keys for encryption and decrption over the data channel. The index refers to
// the short key_id that is passed in the lower 3 bits if a packet header.
// The setup of the keys for a given data channel (that is, for every key_id)
// is made by expanding the keysources using the prf function.
// Do note that we are not yet implementing key renegotiation - but the index
// is provided for convenience when/if we support that in the future.
type dataChannelKey struct {
	index  uint32
	ready  bool
	local  *keySource
	remote *keySource
	mu     sync.Mutex
}

// AddRemoteKey adds the server keySource to our dataChannelKey. This makes the
// dataChannelKey ready to be used.
func (dck *dataChannelKey) AddRemoteKey(k *keySource) error {
	dck.mu.Lock()
	defer dck.mu.Unlock()
	// TODO(ainghazal): this can be done with Once instead
	if dck.ready {
		return fmt.Errorf("%w: %s", errDataChannelKey, "cannot overwrite remote key slot")
	}
	dck.remote = k
	dck.ready = true
	return nil
}

// keySource contains random data to generate keys.
type keySource struct {
	r1        [32]byte
	r2        [32]byte
	preMaster [48]byte
}

// Bytes returns the byte representation of a keySource.
func (k *keySource) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(k.preMaster[:])
	buf.Write(k.r1[:])
	buf.Write(k.r2[:])
	return buf.Bytes()
}

// newKeySource returns a keySource and an error.
func newKeySource() (*keySource, error) {
	random1, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}

	var r1, r2 [32]byte
	var preMaster [48]byte
	copy(r1[:], random1)

	random2, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	copy(r2[:], random2)

	random3, err := randomFn(48)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	copy(preMaster[:], random3)
	return &keySource{
		r1:        r1,
		r2:        r2,
		preMaster: preMaster,
	}, nil
}
