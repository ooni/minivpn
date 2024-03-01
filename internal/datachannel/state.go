package datachannel

import (
	"hash"
	"math"
	"sync"

	"github.com/ooni/minivpn/internal/model"
)

// keySlot holds the different local and remote keys.
type keySlot [64]byte

// dataChannelState is the state of the data channel.
type dataChannelState struct {
	dataCipher dataCipher

	// outgoing and incoming nomenclature is probably more adequate here.
	hmacLocal       hash.Hash
	hmacRemote      hash.Hash
	cipherKeyLocal  keySlot
	cipherKeyRemote keySlot
	hmacKeyLocal    keySlot
	hmacKeyRemote   keySlot

	// TODO(ainghazal): we need to keep a local packetID too. It should be separated from the control channel.
	// TODO: move this to sessionManager perhaps?
	remotePacketID model.PacketID

	hash func() hash.Hash
	mu   sync.Mutex

	// not used at the moment, paving the way for key rotation.
	// keyID           int
}

// SetRemotePacketID stores the passed packetID internally.
func (dcs *dataChannelState) SetRemotePacketID(id model.PacketID) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	dcs.remotePacketID = model.PacketID(id)
}

// RemotePacketID returns the last known remote packetID. It returns an error
// if the stored packet id has reached the maximum capacity of the packetID
// type.
func (dcs *dataChannelState) RemotePacketID() (model.PacketID, error) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	pid := dcs.remotePacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, ErrExpiredKey
	}
	return pid, nil
}
