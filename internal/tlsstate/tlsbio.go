package tlsstate

import (
	"bytes"
	"log"
	"net"
	"sync"
	"time"
)

// tlsBio allows to use channels to read and write
type tlsBio struct {
	closeOnce     sync.Once
	directionDown chan<- []byte
	directionUp   <-chan []byte
	hangup        chan any
	readBuffer    *bytes.Buffer
}

// newTLSBio creates a new tlsBio
func newTLSBio(directionUp <-chan []byte, directionDown chan<- []byte) *tlsBio {
	return &tlsBio{
		closeOnce:     sync.Once{},
		directionDown: directionDown,
		directionUp:   directionUp,
		hangup:        make(chan any),
		readBuffer:    &bytes.Buffer{},
	}
}

func (c *tlsBio) Close() error {
	c.closeOnce.Do(func() {
		close(c.hangup)
	})
	return nil
}

func (c *tlsBio) Read(data []byte) (int, error) {
	for {
		count, _ := c.readBuffer.Read(data)
		if count > 0 {
			log.Printf("[netcoro] received %d bytes", len(data))
			return count, nil
		}
		select { // we are currently blocked here
		case extra := <-c.directionUp:
			c.readBuffer.Write(extra)
		case <-c.hangup:
			return 0, net.ErrClosed
		}
	}
}

func (c *tlsBio) Write(data []byte) (int, error) {
	log.Printf("[netcoro] requested to write %d bytes", len(data))
	select {
	case c.directionDown <- data:
		return len(data), nil
	case <-c.hangup:
		return 0, net.ErrClosed
	}
}

func (c *tlsBio) LocalAddr() net.Addr {
	return &tlsBioAddr{}
}

func (c *tlsBio) RemoteAddr() net.Addr {
	return &tlsBioAddr{}
}

func (c *tlsBio) SetDeadline(t time.Time) error {
	return nil
}

func (c *tlsBio) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *tlsBio) SetWriteDeadline(t time.Time) error {
	return nil
}

// tlsBioAddr is the type of address returned by [Conn]
type tlsBioAddr struct{}

var _ net.Addr = &tlsBioAddr{}

// Network implements net.Addr
func (*tlsBioAddr) Network() string {
	return "tlsBioAddr"
}

// String implements net.Addr
func (*tlsBioAddr) String() string {
	return "tlsBioAddr"
}
