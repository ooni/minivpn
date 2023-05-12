package session

import "github.com/ooni/minivpn/internal/model"

type Manager struct{}

// LocalSessionID gets the local session ID.
func (m *Manager) LocalSessionID() model.SessionID {
}

// IsRemoteSessionIDSet returns whether we've set the remote session ID.
func (m *Manager) IsRemoteSessionIDSet() bool {
}

func (m *Manager) NewACKForPacket(packet *model.Packet) (*model.Packet, error) {
}

// TODO just to make things compile while refactoring
// mocks for data channel
type Session struct {
	LocalSessionID  model.SessionID
	RemoteSessionID model.SessionID
}

func (s *Session) LocalPacketID() (model.PacketID, error) {
	return model.PacketID(0), nil
}
