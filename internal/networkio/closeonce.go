package networkio

import (
	"net"
	"sync"
)

// CloseOnceConn is a [net.Conn] where the Close method has once semantics.
//
// The zero value is invalid; use [NewCloseOnceConn].
type CloseOnceConn struct {
	// once ensures we close just once.
	once sync.Once

	// Conn is the underlying conn.
	net.Conn
}

var _ net.Conn = &CloseOnceConn{}

// NewCloseOnceConn creates a [CloseOnceConn].
func NewCloseOnceConn(conn net.Conn) *CloseOnceConn {
	return &CloseOnceConn{
		once: sync.Once{},
		Conn: conn,
	}
}

// Close implements net.Conn
func (c *CloseOnceConn) Close() (err error) {
	c.once.Do(func() {
		err = c.Conn.Close()
	})
	return
}
