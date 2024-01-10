package networkio

import (
	"context"

	"github.com/ooni/minivpn/internal/model"
)

// Dialer dials network connections. The zero value of this structure is
// invalid; please, use the [NewDialer] constructor.
type Dialer struct {
	// dialer is the underlying [DialerContext] we use to dial.
	dialer model.Dialer

	// logger is the [Logger] with which we log.
	logger model.Logger
}

// NewDialer creates a new [Dialer] instance.
func NewDialer(logger model.Logger, dialer model.Dialer) *Dialer {
	return &Dialer{
		dialer: dialer,
		logger: logger,
	}
}

// DialContext establishes a connection and, on success, automatically wraps the
// returned connection to implement OpenVPN framing when not using UDP.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (FramingConn, error) {
	// dial with the underlying dialer
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		d.logger.Warnf("networkio: dial failed: %s", err.Error())
		return nil, err
	}

	d.logger.Debugf("networkio: connected to %s/%s", address, network)

	// make sure the conn has close once semantics
	conn = newCloseOnceConn(conn)

	// wrap the conn and return
	switch conn.LocalAddr().Network() {
	case "udp", "udp4", "udp6":
		return &datagramConn{conn}, nil
	default:
		return &streamConn{conn}, nil
	}
}
