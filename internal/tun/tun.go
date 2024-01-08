// Package tun implements the tun API for the minivpn client.
// TODO(ainghazal): this package is almost identical to tlsbio, consider refactoring.

package tun

import (
	"bytes"
	"log"
	"net"
	"sync"
	"time"
)

// tunBio allows to use channels to read and write
type TUNBio struct {
	closeOnce  sync.Once
	TunDown    chan []byte
	TunUp      chan []byte
	hangup     chan any
	readBuffer *bytes.Buffer
}

// newTUNBio creates a new tunBio
func NewTUNBio() *TUNBio {
	return &TUNBio{
		closeOnce: sync.Once{},
		TunDown:   make(chan []byte),
		TunUp:     make(chan []byte),
		hangup:    make(chan any),
		// we don't need the read buffer in this case do we?
		readBuffer: &bytes.Buffer{},
	}
}

func (t *TUNBio) Close() error {
	t.closeOnce.Do(func() {
		close(t.hangup)
	})
	return nil
}

func (t *TUNBio) Read(data []byte) (int, error) {
	for {
		count, _ := t.readBuffer.Read(data)
		if count > 0 {
			log.Printf("[tunbio] received %d bytes", len(data))
			return count, nil
		}
		select {
		case extra := <-t.TunUp:
			t.readBuffer.Write(extra)
		case <-t.hangup:
			return 0, net.ErrClosed
		}
	}
}

func (t *TUNBio) Write(data []byte) (int, error) {
	log.Printf("[tunbio] requested to write %d bytes", len(data))
	select {
	case t.TunDown <- data:
		return len(data), nil
	case <-t.hangup:
		return 0, net.ErrClosed
	}
}

func (t *TUNBio) LocalAddr() net.Addr {
	return &tunBioAddr{}
}

func (t *TUNBio) RemoteAddr() net.Addr {
	return &tunBioAddr{}
}

func (c *TUNBio) SetDeadline(t time.Time) error {
	return nil
}

func (c *TUNBio) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *TUNBio) SetWriteDeadline(t time.Time) error {
	return nil
}

// tunBioAddr is the type of address returned by [Conn]
type tunBioAddr struct{}

var _ net.Addr = &tunBioAddr{}

// Network implements net.Addr
func (*tunBioAddr) Network() string {
	return "tunBioAddr"
}

// String implements net.Addr
func (*tunBioAddr) String() string {
	return "tunBioAddr"
}
