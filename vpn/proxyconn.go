package vpn

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// proxyConnDeadline is an abstraction for handling timeouts.
//
// Adapted from src/net/pipe.go.
//
// SPDX-License-Identifier: BSD-3-Clause.
type proxyConnDeadline struct {
	// mu provides mutual exclusion.
	mu sync.Mutex

	// timer is the possibly-nil timer determining
	// when the deadline (if any) has expired.
	timer *time.Timer

	// cancel must be non-nil and is the channel
	// closed when the deadline expires.
	cancel chan interface{}
}

// newChanConnDeadline creates a new [chanConnDeadline].
//
// Adapted from src/net/pipe.go.
//
// SPDX-License-Identifier: BSD-3-Clause.
func newChanConnDeadline() proxyConnDeadline {
	return proxyConnDeadline{cancel: make(chan interface{})}
}

// set sets the point in time when the deadline will time out.
// A timeout event is signaled by closing the channel returned by waiter.
// Once a timeout has occurred, the deadline can be refreshed by specifying a
// t value in the future.
//
// A zero value for t prevents timeout.
//
// Adapted from src/net/pipe.go.
//
// SPDX-License-Identifier: BSD-3-Clause.
func (d *proxyConnDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // Wait for the timer callback to finish and close cancel
	}
	d.timer = nil

	// Time is zero, then there is no deadline.
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan interface{})
		}
		return
	}

	// Time in the future, setup a timer to cancel in the future.
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan interface{})
		}
		d.timer = time.AfterFunc(dur, func() {
			close(d.cancel)
		})
		return
	}

	// Time in the past, so close immediately.
	if !closed {
		close(d.cancel)
	}
}

// wait returns a channel that is closed when the deadline is exceeded.
//
// Adapted from src/net/pipe.go.
//
// SPDX-License-Identifier: BSD-3-Clause.
func (d *proxyConnDeadline) wait() chan interface{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

// isClosedChan returns whether a channel is closed.
//
// Adapted from src/net/pipe.go.
//
// SPDX-License-Identifier: BSD-3-Clause.
func isClosedChan(c <-chan interface{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// proxyConn is a [net.Conn] attached to a pair of channels. We designed this
// struct to help with implementing dispatching to the control and data channels
// of the OpenVPN protocol. The zero value of this struct is invalid; please,
// use the [newChanConn] constructor to create a new instance.
type proxyConn struct {
	// closed is closed by [ChanConn.Close].
	closed chan interface{}

	// closeOnce ensures that we close [ChanConn.closed] just once.
	closeOnce sync.Once

	// incomingData contains the data read by [ChannConn.Read].
	incomingData [][]byte

	// incomingMu protects [chanConn.incoming].
	incomingMu sync.Mutex

	// incomingNotify is posted when incoming data is available.
	incomingNotify chan interface{}

	// outgoing is where [ChanConn.Write] writes bytes.
	outgoing chan []byte

	// readDeadline is the read deadline.
	readDeadline proxyConnDeadline

	// wantRead is posted when [ChanConn.Read] blocks.
	wantRead chan interface{}

	// writeDeadline is the write deadline.
	writeDeadline proxyConnDeadline
}

var _ net.Conn = &proxyConn{}

// newChanConn creates a new [chanConn] using a private outgoing chan.
func newChanConn() *proxyConn {
	return newChanConnWithOutgoingChan(make(chan []byte))
}

// newChanConnWithOutgoingChan creates a new [chanConn] using a given outgoing chan.
func newChanConnWithOutgoingChan(outgoing chan []byte) *proxyConn {
	conn := &proxyConn{
		closed:         make(chan any),
		closeOnce:      sync.Once{},
		incomingData:   nil,
		incomingMu:     sync.Mutex{},
		incomingNotify: make(chan any, 1),
		outgoing:       outgoing,
		readDeadline:   newChanConnDeadline(),
		wantRead:       make(chan any, 1),
		writeDeadline:  newChanConnDeadline(),
	}
	return conn
}

// Close implements net.Conn
func (c *proxyConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

// Closed returns the channel closed when the connection has been closed.
func (c *proxyConn) Closed() <-chan any {
	return c.closed
}

// Read implements net.Conn
func (c *proxyConn) Read(data []byte) (int, error) {
	c.incomingMu.Lock()
	for len(c.incomingData) <= 0 {
		c.incomingMu.Unlock()

		// notify the goroutine that is filling the conn with
		// incoming data that we're blocking on reading
		select {
		case c.wantRead <- true:
		default:
		}

		// wait for incoming data, deadline, or EOF
		select {
		case <-c.closed:
			return 0, io.ErrClosedPipe
		case <-c.readDeadline.wait():
			return 0, os.ErrDeadlineExceeded
		case <-c.incomingNotify:
			// fallthrough
		}

		c.incomingMu.Lock()
	}
	defer c.incomingMu.Unlock()

	// read bytes from the front of the incoming queue
	n := copy(data, c.incomingData[0])
	c.incomingData[0] = c.incomingData[0][n:]
	if len(c.incomingData[0]) <= 0 {
		c.incomingData = c.incomingData[1:]
	}

	return n, nil
}

// WantRead is the channel posted every time [chanConn.Read] blocks.
func (c *proxyConn) WantRead() <-chan interface{} {
	return c.wantRead
}

// AppendIncomingData locks the incoming data buffer and appends incoming data. This method
// does not send a notification to a possibly blocked reader.
func (c *proxyConn) AppendIncomingData(data []byte) {
	c.incomingMu.Lock()
	c.incomingData = append(c.incomingData, data)
	c.incomingMu.Unlock()
}

// NotifyIncoming returns the channel whether to notify about incoming data. You should
// use the following pattern to invoke this method:
//
//	conn.AppendIncomingData(data)
//	select {
//	case conn.NotifyIncomingData() <- true:
//	default:
//	}
//
// Because the returned channel has a buffer size equal to one, the above code will always
// block a stuck receiver as long as there is a single goroutine that receives. At the same
// time, this code would not block waiting for another goroutine to call [chanConn.Read].
func (c *proxyConn) NotifyIncoming() chan<- interface{} {
	return c.incomingNotify
}

// Write implements net.Conn
func (c *proxyConn) Write(data []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case <-c.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	case c.outgoing <- data:
		return len(data), nil
	}
}

// OutgoingData returns the channel containing outgoing data. You should use the
// following pattern to use this method:
//
//	select {
//	case data := <-conn.OutgoingData():
//	case <-conn.Closed():
//		return
//	}
func (c *proxyConn) OutgoingData() <-chan []byte {
	return c.outgoing
}

// LocalAddr implements net.Conn
func (c *proxyConn) LocalAddr() net.Addr {
	return &chanConnAddr{}
}

// RemoteAddr implements net.Conn
func (c *proxyConn) RemoteAddr() net.Addr {
	return &chanConnAddr{}
}

// SetDeadline implements net.Conn
func (c *proxyConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn
func (c *proxyConn) SetReadDeadline(t time.Time) error {
	if isClosedChan(c.closed) {
		return io.ErrClosedPipe
	}
	c.readDeadline.set(t)
	return nil
}

// SetWriteDeadline implements net.Conn
func (c *proxyConn) SetWriteDeadline(t time.Time) error {
	if isClosedChan(c.closed) {
		return io.ErrClosedPipe
	}
	c.writeDeadline.set(t)
	return nil
}

// chanConnAddr is the address returned by [PipeConn].
type chanConnAddr struct{}

var _ net.Addr = &chanConnAddr{}

// Network implements net.Addr
func (a *chanConnAddr) Network() string {
	return "chan"
}

// String implements net.Addr
func (a *chanConnAddr) String() string {
	return "chan"
}
