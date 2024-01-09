// Package tun implements the tun API for the minivpn client.

// TODO(ainghazal): this package is almost identical to tlsbio, consider refactoring.

package tun

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
)

// tunBio allows to use channels to read and write
// TODO pass logger
type TUNBio struct {
	closeOnce        sync.Once
	TunDown          chan []byte
	TunUp            chan []byte
	hangup           chan any
	readBuffer       *bytes.Buffer
	session          *session.Manager
	Workers          *workers.Manager
	readDeadline     *time.Timer
	readDeadlineDone chan any
}

// newTUNBio creates a new tunBio
func NewTUNBio(session *session.Manager) *TUNBio {
	return &TUNBio{
		closeOnce: sync.Once{},
		TunDown:   make(chan []byte),
		TunUp:     make(chan []byte, 10),
		hangup:    make(chan any),
		// we don't need the read buffer in this case do we?
		readBuffer:       &bytes.Buffer{},
		session:          session,
		readDeadlineDone: make(chan any),
	}
}

func (t *TUNBio) Close() error {
	t.closeOnce.Do(func() {
		close(t.hangup)
		fmt.Println("closed! start shutdown")
		t.Workers.StartShutdown()
	})
	return nil
}

func (t *TUNBio) Read(data []byte) (int, error) {
	// log.Printf("[tunbio] requested read")
	for {
		count, _ := t.readBuffer.Read(data)
		if count > 0 {
			// log.Printf("[tunbio] received %d bytes", len(data))
			return count, nil
		}
		select {
		case <-t.readDeadlineDone:
			return 0, context.DeadlineExceeded
		case extra := <-t.TunUp:
			t.readBuffer.Write(extra)
		case <-t.hangup:
			return 0, net.ErrClosed
		}
	}
}

func (t *TUNBio) Write(data []byte) (int, error) {
	// log.Printf("[tunbio] requested to write %d bytes", len(data))
	select {
	case t.TunDown <- data:
		return len(data), nil
	case <-t.hangup:
		return 0, net.ErrClosed
	}
}

// These methods are specific for TUNBio, not in TLSBio

func (t *TUNBio) LocalAddr() net.Addr {
	// TODO block or fail if session not ready
	ip := t.session.TunnelInfo().IP
	return &tunBioAddr{ip}
}

func (t *TUNBio) RemoteAddr() net.Addr {
	// TODO block or fail if session not ready
	gw := t.session.TunnelInfo().GW
	return &tunBioAddr{gw}
}

func (t *TUNBio) SetDeadline(tm time.Time) error {
	log.Println("TODO should set deadline", t)
	return nil
}

func (t *TUNBio) SetReadDeadline(tm time.Time) error {
	// If there's an existing timer, stop it
	if t.readDeadline != nil {
		t.readDeadline.Stop()
	}
	// Calculate the duration until the deadline
	duration := time.Until(tm)
	// Create a new timer
	t.readDeadline = time.AfterFunc(duration, func() {
		t.readDeadlineDone <- true
	})
	return nil
}

func (c *TUNBio) SetWriteDeadline(t time.Time) error {
	log.Println("TODO should set write deadline", t)
	return nil
}

// tunBioAddr is the type of address returned by [Conn]
type tunBioAddr struct {
	addr string
}

var _ net.Addr = &tunBioAddr{}

// Network implements net.Addr
func (t *tunBioAddr) Network() string {
	return "tunBioAddr"
}

// String implements net.Addr
func (t *tunBioAddr) String() string {
	return t.addr
}
