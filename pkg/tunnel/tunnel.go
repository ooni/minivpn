// Package tunnel contains the public tunnel API.
package tunnel

import (
	"context"
	"net"

	"github.com/ooni/minivpn/internal/networkio"
	"github.com/ooni/minivpn/internal/tun"
	"github.com/ooni/minivpn/pkg/config"

	"github.com/apex/log"
)

// SimpleDialer establishes network connections.
type SimpleDialer interface {
	DialContext(ctx context.Context, network, endpoint string) (net.Conn, error)
}

// We're creating a type alias to expose the internal TUN implementation on the public API.
type TUN = tun.TUN

// Start starts a VPN tunnel initialized with the passed dialer and config, and returns a TUN device
// that can later be stopped. In case there was any error during the initialization of the tunnel,
// they will also be returned by this function.
func Start(ctx context.Context, underlyingDialer SimpleDialer, cfg *config.Config) (*TUN, error) {
	dialer := networkio.NewDialer(cfg.Logger(), underlyingDialer)
	conn, err := dialer.DialContext(ctx, cfg.Remote().Protocol, cfg.Remote().Endpoint)
	if err != nil {
		log.WithError(err).Error("dialer.DialContext")
		return nil, err
	}
	return tun.StartTUN(ctx, conn, cfg)
}
