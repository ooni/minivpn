package vpn

import (
	"context"
	"io"
	"net"
	"time"
)

// NetworkContextDialer is a dialer using a context.
type NetworkContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NetworkDialerRequest is a request to dial a connection.
type NetworkDialerRequest struct {
	// Address is the destination address.
	Address string

	// Dialer is the dialer to use for dialing.
	Dialer NetworkContextDialer

	// Network is the network to use.
	Network string

	// Timeout is the timeout for dialing.
	Timeout time.Duration
}

// NetworkDialerService is the service performing network dials. The zero value
// is invalid; please, use [startNetworkDialerService] to construct.
type NetworkDialerService struct {
	// Request is the channel where you post a request to perform a dial. The service
	// will service your request in its service goroutine posting the result either on
	// either the Success or the Failure channel.
	Request chan<- *NetworkDialerRequest

	// Success is where the service will post a successful dial result.
	Success <-chan net.Conn

	// Failure is where the service will post a failed dial result.
	Failure <-chan error
}

// StartNetworkDialerService starts the [networkDialerService] in a background
// goroutine. The goroutine will run until the context is not done.
func StartNetworkDialerService(ctx context.Context) *NetworkDialerService {
	var (
		request = make(chan *NetworkDialerRequest)
		success = make(chan net.Conn)
		failure = make(chan error)
	)
	go networkDialerServiceMain(ctx, request, success, failure)
	svc := &NetworkDialerService{
		Request: request,
		Success: success,
		Failure: failure,
	}
	return svc
}

// networkDialerServiceMain is the [networkDialerService] main function.
func networkDialerServiceMain(
	ctx context.Context,
	request <-chan *NetworkDialerRequest,
	success chan<- net.Conn,
	failure chan<- error,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-request:
			networkDialerServiceDo(ctx, req, success, failure)
		}
	}
}

// networkDialerServiceDo performs the dial.
func networkDialerServiceDo(
	ctx context.Context,
	req *NetworkDialerRequest,
	success chan<- net.Conn,
	failure chan<- error,
) {
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	conn, err := req.Dialer.DialContext(ctx, req.Network, req.Address)
	if err != nil {
		select {
		case failure <- err:
		case <-ctx.Done():
		}
		return
	}
	select {
	case success <- conn:
	case <-ctx.Done():
		conn.Close()
	}
}

// AttachPipe attaches one end of a [net.Pipe] to the given BORROWED [net.Conn], spawns
// a background goroutine to perform I/O and returns the other end of the [net.Pipe]. The
// background goroutine will continue running until there's an I/O error. The caller of
// thid function OWNS the returned conn and MUST close it when done.
func AttachPipe(borrowed net.Conn) net.Conn {
	left, right := net.Pipe()
	go pipeOwnAndCopyTo(left, borrowed)
	go pipeBorrowAndCopyTo(borrowed, left)
	return right
}

// pipeOwnAndCopyTo owns left and copies from left to right.
func pipeOwnAndCopyTo(left, right net.Conn) {
	defer left.Close()
	pipeBorrowAndCopyTo(left, right)
}

// pipeBorrowAndCopyTo borrows left and copies from left to right.
func pipeBorrowAndCopyTo(left, right net.Conn) {
	_, _ = io.Copy(right, left)
}
