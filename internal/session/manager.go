package session

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
	"github.com/ooni/minivpn/internal/runtimex"
)

// SessionNegotiationState is the state of the session negotiation.
type SessionNegotiationState int

const (
	// S_ERROR means there was some form of protocol error.
	S_ERROR = SessionNegotiationState(iota) - 1

	// S_UNDER is the undefined state.
	S_UNDEF

	// S_INITIAL means we're ready to begin the three-way handshake.
	S_INITIAL

	// S_PRE_START means we're waiting for acknowledgment from the remote.
	S_PRE_START

	// S_START means we've done the three-way handshake.
	S_START

	// S_SENT_KEY means we have sent the local part of the key_source2 random material.
	S_SENT_KEY

	// S_GOT_KEY means we have got the remote part of key_source2.
	S_GOT_KEY

	// S_ACTIVE means the control channel was established.
	S_ACTIVE

	// S_GENERATED_KEYS means the data channel keys have been generated.
	S_GENERATED_KEYS
)

// String maps a [SessionNegotiationState] to a string.
func (sns SessionNegotiationState) String() string {
	switch sns {
	case S_UNDEF:
		return "S_UNDEF"
	case S_INITIAL:
		return "S_INITIAL"
	case S_PRE_START:
		return "S_PRE_START"
	case S_START:
		return "S_START"
	case S_SENT_KEY:
		return "S_SENT_KEY"
	case S_GOT_KEY:
		return "S_GOT_KEY"
	case S_ACTIVE:
		return "S_ACTIVE"
	case S_GENERATED_KEYS:
		return "S_GENERATED_KEYS"
	case S_ERROR:
		return "S_ERROR"
	default:
		return "S_INVALID"
	}
}

// Manager manages the session. The zero value is invalid. Please, construct
// using [NewManager]. This struct is concurrency safe.
type Manager struct {
	keyID                uint8
	keys                 []*DataChannelKey
	localControlPacketID model.PacketID
	localDataPacketID    model.PacketID
	localSessionID       model.SessionID
	logger               model.Logger
	mu                   sync.Mutex
	negState             SessionNegotiationState
	remoteSessionID      optional.Value[model.SessionID]
	tunnelInfo           model.TunnelInfo

	// Ready is a channel where we signal that we can start accepting data, because we've
	// successfully generated key material for the data channel.
	// TODO(ainghazal): find a better way?
	Ready chan any
}

// NewManager returns a [Manager] ready to be used.
func NewManager(logger model.Logger) (*Manager, error) {
	key0 := &DataChannelKey{}
	sessionManager := &Manager{
		keyID:           0,
		keys:            []*DataChannelKey{key0},
		localSessionID:  [8]byte{},
		logger:          logger,
		mu:              sync.Mutex{},
		negState:        0,
		remoteSessionID: optional.None[model.SessionID](),
		tunnelInfo:      model.TunnelInfo{},

		// empirically, it seems that the reference OpenVPN server misbehaves if we initialize
		// the data packet ID counter to zero.
		localDataPacketID: 1,

		Ready: make(chan any),
	}

	randomBytes, err := randomFn(8)
	if err != nil {
		return sessionManager, err
	}

	sessionManager.localSessionID = (model.SessionID)(randomBytes[:8])

	localKey, err := NewKeySource()
	if err != nil {
		return sessionManager, err
	}

	k, err := sessionManager.ActiveKey()
	if err != nil {
		return sessionManager, err
	}
	k.local = localKey
	return sessionManager, nil
}

// LocalSessionID gets the local session ID as bytes.
func (m *Manager) LocalSessionID() []byte {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.localSessionID[:]
}

// RemoteSessionID gets the remote session ID as bytes.
func (m *Manager) RemoteSessionID() []byte {
	defer m.mu.Unlock()
	m.mu.Lock()
	rs := m.remoteSessionID
	if !rs.IsNone() {
		val := rs.Unwrap()
		return val[:]
	}
	return nil
}

// IsRemoteSessionIDSet returns whether we've set the remote session ID.
func (m *Manager) IsRemoteSessionIDSet() bool {
	defer m.mu.Unlock()
	m.mu.Lock()
	return !m.remoteSessionID.IsNone()
}

// ErrNoRemoteSessionID indicates we are missing the remote session ID.
var ErrNoRemoteSessionID = errors.New("missing remote session ID")

// NewACKForPacket creates a new ACK for the given packet.
func (m *Manager) NewACKForPacket(packet *model.Packet) (*model.Packet, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	if m.remoteSessionID.IsNone() {
		return nil, ErrNoRemoteSessionID
	}
	p := &model.Packet{
		Opcode:          model.P_ACK_V1,
		KeyID:           m.keyID,
		PeerID:          [3]byte{},
		LocalSessionID:  m.localSessionID,
		ACKs:            []model.PacketID{packet.ID},
		RemoteSessionID: m.remoteSessionID.Unwrap(),
		ID:              0,
		Payload:         []byte{},
	}
	return p, nil
}

// NewPacket creates a new packet for this session.
func (m *Manager) NewPacket(opcode model.Opcode, payload []byte) (*model.Packet, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	// TODO: consider unifying with ACKing code
	packet := model.NewPacket(
		opcode,
		m.keyID,
		payload,
	)
	copy(packet.LocalSessionID[:], m.localSessionID[:])
	pid, err := func() (model.PacketID, error) {
		if opcode.IsControl() {
			return m.localControlPacketIDLocked()
		} else {
			return m.localDataPacketIDLocked()
		}
	}()
	if err != nil {
		return nil, err
	}
	packet.ID = pid
	if !m.remoteSessionID.IsNone() {
		packet.RemoteSessionID = m.remoteSessionID.Unwrap()
	}
	return packet, nil
}

var ErrExpiredKey = errors.New("expired key")

// LocalDataPacketID returns an unique Packet ID for the Data Channel. It
// increments the counter for the local data packet ID.
func (m *Manager) LocalDataPacketID() (model.PacketID, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.localDataPacketIDLocked()
}

// localDataPacketIDLocked returns an unique Packet ID for the Data Channel. It
// increments the counter for the local data packet ID.
func (m *Manager) localDataPacketIDLocked() (model.PacketID, error) {
	pid := m.localDataPacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, ErrExpiredKey
	}
	m.localDataPacketID++
	return pid, nil
}

// localControlPacketIDLocked returns an unique Packet ID for the Control Channel. It
// increments the counter for the local control packet ID.
func (m *Manager) localControlPacketIDLocked() (model.PacketID, error) {
	pid := m.localControlPacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, ErrExpiredKey
	}
	m.localControlPacketID++
	return pid, nil
}

// NegotiationState returns the state of the negotiation.
func (m *Manager) NegotiationState() SessionNegotiationState {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.negState
}

// SetNegotiationState sets the state of the negotiation.
func (m *Manager) SetNegotiationState(sns SessionNegotiationState) {
	defer m.mu.Unlock()
	m.mu.Lock()
	m.logger.Infof("[@] %s -> %s", m.negState, sns)
	m.negState = sns
	if sns == S_GENERATED_KEYS {
		m.Ready <- true
	}
}

// ActiveKey returns the dataChannelKey that is actively being used.
func (m *Manager) ActiveKey() (*DataChannelKey, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	if len(m.keys) > math.MaxUint8 || m.keyID >= uint8(len(m.keys)) {
		return nil, fmt.Errorf("%w: %s", errDataChannelKey, "no such key id")
	}
	dck := m.keys[m.keyID]
	// TODO(bassosimone): the following code would prevent us from
	// creating a new session at the beginning--refactor?
	/*
		if !dck.Ready() {
			return nil, fmt.Errorf("%w: %s", errDataChannelKey, "not ready")
		}
	*/
	return dck, nil
}

// SetRemoteSessionID sets the remote session ID.
func (m *Manager) SetRemoteSessionID(remoteSessionID model.SessionID) {
	defer m.mu.Unlock()
	m.mu.Lock()
	runtimex.Assert(m.remoteSessionID.IsNone(), "SetRemoteSessionID called more than once")
	m.remoteSessionID = optional.Some(remoteSessionID)
}

func (m *Manager) CurrentKeyID() uint8 {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.keyID
}

// InitTunnelInfo initializes TunnelInfo from data obtained from the auth response.
func (m *Manager) InitTunnelInfo(remoteOption string) error {
	defer m.mu.Unlock()
	m.mu.Lock()
	ti, err := newTunnelInfoFromRemoteOptionsString(remoteOption)
	if err != nil {
		return err
	}
	m.tunnelInfo = *ti
	m.logger.Infof("Tunnel MTU: %v", m.tunnelInfo.MTU)
	return nil
}

// newTunnelInfoFromRemoteOptionsString parses the options string returned by
// server. It returns a new tunnelInfo object where the needed fields have been
// updated. At the moment, we only parse the tun-mtu parameter.
func newTunnelInfoFromRemoteOptionsString(remoteOpts string) (*model.TunnelInfo, error) {
	t := &model.TunnelInfo{}
	opts := strings.Split(remoteOpts, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		if len(vals) < 2 {
			continue
		}
		k, v := vals[0], vals[1:]
		if k == "tun-mtu" {
			mtu, err := strconv.Atoi(v[0])
			if err != nil {
				return nil, err
			}
			t.MTU = mtu
		}
	}
	return t, nil
}

// UpdateTunnelInfo updates the internal tunnel info from the push response message
func (m *Manager) UpdateTunnelInfo(ti *model.TunnelInfo) {
	defer m.mu.Unlock()
	m.mu.Lock()

	m.tunnelInfo.IP = ti.IP
	m.tunnelInfo.GW = ti.GW
	m.tunnelInfo.PeerID = ti.PeerID
	m.tunnelInfo.NetMask = ti.NetMask

	m.logger.Infof("Tunnel IP: %s", ti.IP)
	m.logger.Infof("Gateway IP: %s", ti.GW)
	m.logger.Infof("Peer ID: %d", ti.PeerID)
}

// TunnelInfo returns a copy the current TunnelInfo
func (m *Manager) TunnelInfo() model.TunnelInfo {
	defer m.mu.Unlock()
	m.mu.Lock()
	return model.TunnelInfo{
		GW:      m.tunnelInfo.GW,
		IP:      m.tunnelInfo.IP,
		MTU:     m.tunnelInfo.MTU,
		NetMask: m.tunnelInfo.NetMask,
		PeerID:  m.tunnelInfo.PeerID,
	}
}
