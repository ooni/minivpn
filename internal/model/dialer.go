package model

import (
	"context"
	"net"
)

// Dialer is a type allowing to dial network connections.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
