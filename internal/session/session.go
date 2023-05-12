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
type Session struct{}
