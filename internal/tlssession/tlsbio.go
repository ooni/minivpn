package tlssession

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
)

// tlsBio allows to use channels to read and write
type tlsBio struct {
	closeOnce     sync.Once
	directionDown chan<- []byte
	directionUp   <-chan []byte
	hangup        chan any
	logger        model.Logger
	readBuffer    *bytes.Buffer
}

// newTLSBio creates a new tlsBio
func newTLSBio(logger model.Logger, directionUp <-chan []byte, directionDown chan<- []byte) *tlsBio {
	return &tlsBio{
		closeOnce:     sync.Once{},
		directionDown: directionDown,
		directionUp:   directionUp,
		hangup:        make(chan any),
		logger:        logger,
		readBuffer:    &bytes.Buffer{},
	}
}

func (t *tlsBio) Close() error {
	t.closeOnce.Do(func() {
		close(t.hangup)
	})
	return nil
}

func (t *tlsBio) Read(data []byte) (int, error) {
	for {
		count, _ := t.readBuffer.Read(data)
		if count > 0 {
			t.logger.Debugf("[tlsbio] received %d bytes", len(data))
			return count, nil
		}
		select {
		case extra := <-t.directionUp:
			t.readBuffer.Write(extra)
		case <-t.hangup:
			return 0, net.ErrClosed
		}
	}
}

func (t *tlsBio) Write(data []byte) (int, error) {
	t.logger.Debugf("[tlsbio] requested to write %d bytes", len(data))
	select {
	case t.directionDown <- data:
		return len(data), nil
	case <-t.hangup:
		return 0, net.ErrClosed
	}
}

func (t *tlsBio) LocalAddr() net.Addr {
	return &tlsBioAddr{}
}

func (t *tlsBio) RemoteAddr() net.Addr {
	return &tlsBioAddr{}
}

func (t *tlsBio) SetDeadline(tt time.Time) error {
	return nil
}

func (t *tlsBio) SetReadDeadline(tt time.Time) error {
	return nil
}

func (t *tlsBio) SetWriteDeadline(tt time.Time) error {
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
