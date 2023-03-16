// obfs4 connection wrappers
//
// SPDX-License-Identifier: MIT
// (c) 2015-2022 rhui zheng
// (c) 2015-2022 ginuerzh and gost contributors
// (c) 2021 Simone Basso
// (c) 2022 Ain Ghazal

// Code in this package is derived from:
// https://github.com/ginuerzh/gost
// It also borrows functions from ooni/probe-cli/internal/ptx/obfs4.go

// These convenience functions might be removed in the future in favor of reusing
// OONI's probe_cli/internal/ptx/obfs4.go dialers. For the time being I'm exploring
// the utility of providing adaptors for other gost transports.

package obfs4

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	pt "git.torproject.org/pluggable-transports/goptlib.git"

	"gitlab.com/yawning/obfs4.git/transports/base"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
)

// simpleDialer establishes network connections.
type simpleDialer interface {
	// DialContext behaves like net.Dialer.DialContext.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ObfuscationDialer is a dialer for obfs4.
type ObfuscationDialer struct {
	node *ProxyNode
	// Dialer is the optional underlying dialer to
	// use. If not set, we will use &net.Dialer{}.
	UnderlyingDialer simpleDialer
}

func NewDialer(node *ProxyNode) *ObfuscationDialer {
	return &ObfuscationDialer{node, nil}
}

// underlyingDialer returns a suitable simpleDialer.
func (d *ObfuscationDialer) underlyingDialer() simpleDialer {
	if d.UnderlyingDialer != nil {
		return d.UnderlyingDialer
	}
	return &net.Dialer{
		Timeout: 15 * time.Second, // eventually interrupt connect
	}
}

// DialContext establishes a connection with the given obfs4 proxy. The context
// argument allows to interrupt this operation midway.
func (d *ObfuscationDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	cd, err := d.newCancellableDialer()
	if err != nil {
		return nil, err
	}
	return cd.dial(ctx, "tcp", d.node.Addr)
}

// newCancellableDialer constructs a new cancellable dialer. This function
// is separate from DialContext for testing purposes.
func (d *ObfuscationDialer) newCancellableDialer() (*obfs4CancellableDialer, error) {
	return &obfs4CancellableDialer{
		done: make(chan interface{}),
		ud:   d.underlyingDialer(), // choose proper dialer
	}, nil
}

// obfs4CancellableDialer is a cancellable dialer for obfs4. It will run
// the dial proper in a background goroutine, thus allowing for its early
// cancellation.
type obfs4CancellableDialer struct {
	// done is a channel that will be closed when done. In normal
	// usage you don't want to await for this signal. But it's useful
	// for testing to know that the background goroutine joined.
	done chan interface{}

	// ud is the underlying Dialer to use.
	ud simpleDialer
}

// dial performs the dial.
func (d *obfs4CancellableDialer) dial(
	ctx context.Context, network, address string) (net.Conn, error) {
	connch, errch := make(chan net.Conn), make(chan error, 1)

	oc := obfs4Map[address]

	go func() {
		defer close(d.done) // signal we're joining
		conn, err := oc.cf.Dial(network, address, d.innerDial, oc.cargs)
		if err != nil {
			errch <- err // buffered channel
			return
		}
		select {
		case connch <- conn:
		default:
			conn.Close() // context won the race
		}
	}()
	select {
	case err := <-errch:
		return nil, err
	case conn := <-connch:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// innerDial performs the inner dial using the underlying dialer.
func (d *obfs4CancellableDialer) innerDial(network, address string) (net.Conn, error) {
	return d.ud.DialContext(context.Background(), network, address)
}

// obfs4Context holds references to a clientFactory and the parsed arguments
type obfs4Context struct {
	cf    base.ClientFactory
	cargs interface{} // type obfs4ClientArgs
}

// obfsMap is a global map where to lookup obfs4Context for a given address
var obfs4Map = make(map[string]obfs4Context)

// Init initializes the obfs4 client
// The server certificate given to the client is in the following format:
// obfs4://server_ip:443?cert=4UbQjIfjJEQHPOs8vs5sagrSXx1gfrDCGdVh2hpIPSKH0nklv1e4f29r7jb91VIrq4q5Jw&iat-mode=0'
// be sure to urlencode the certificate you obtain from obfs4proxy or other software.
func Init(node *ProxyNode) error {
	if _, ok := obfs4Map[node.Addr]; ok {
		return fmt.Errorf("obfs4 context already initialized")
	}

	t := new(obfs4.Transport)

	stateDir := node.Values.Get("state-dir")
	if stateDir == "" {
		stateDir = "."
	}

	ptArgs := pt.Args(node.Values)

	// we're only dealing with the client side here, we assume
	// server side is running obfs4proxy or the likes. in the future it would perhaps be
	// nice to support other obfs4-based transporters as gost is doing.
	cf, err := t.ClientFactory(stateDir)
	if err != nil {
		log.Println("obfs4: error on clientFactory")
		return err
	}

	cargs, err := cf.ParseArgs(&ptArgs)
	if err != nil {
		log.Println("error on parseArgs:", err.Error())
		return err
	}

	// add the address entry to the context map
	obfs4Map[node.Addr] = obfs4Context{cf: cf, cargs: cargs}
	return nil
}
