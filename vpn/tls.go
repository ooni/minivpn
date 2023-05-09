package vpn

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// TLSClientConn is a TLS client connection.
type TLSClientConn interface {
	// A tlsClientConn is a net.Conn
	net.Conn

	// HandshakeContext performs the TLS handshake.
	HandshakeContext(ctx context.Context) error
}

// TLSClientFactory constructs TLS client connections.
type TLSClientFactory interface {
	NewClientConn(conn net.Conn, config *tls.Config) TLSClientConn
}

// TLSHandshakeRequest is a request to perform a TLS handshake.
type TLSHandshakeRequest struct {
	// Config is the TLS configuration.
	Config *tls.Config

	// Conn is underlying TCP/UDP connection.
	Conn net.Conn

	// Factory is the TLS conn factory.
	Factory TLSClientFactory

	// Timeout is the timeout for the handshake.
	Timeout time.Duration
}

// TLSHandshakeService is the service performing TLS handshakes. The zero value of this
// struct is invalid; please, use [startTLSHandshakeService] to construct.
type TLSHandshakeService struct {
	// Request is the channel where you post a request to perform a TLS handshake
	// using a given conn. The service will service your request in its service
	// goroutine posting the result either on the Success or the Failure channel.
	Request chan<- *TLSHandshakeRequest

	// Success is where the service will post a successful handshake result.
	Success <-chan net.Conn

	// Failure is where the service will post a failed handshake result.
	Failure <-chan error
}

// StartTLSHandshakeService starts the [tlsHandshakeService] in a background
// goroutine. The goroutine will run until the context is not done.
func StartTLSHandshakeService(ctx context.Context) *TLSHandshakeService {
	var (
		request = make(chan *TLSHandshakeRequest)
		success = make(chan net.Conn)
		failure = make(chan error)
	)
	go tlsHandshakeServiceMain(ctx, request, success, failure)
	svc := &TLSHandshakeService{
		Request: request,
		Success: success,
		Failure: failure,
	}
	return svc
}

// tlsHandshakeServiceMain is the [tlsHandshakeService] main function.
func tlsHandshakeServiceMain(
	ctx context.Context,
	request <-chan *TLSHandshakeRequest,
	success chan<- net.Conn,
	failure chan<- error,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-request:
			tlsHandshakeServiceDo(ctx, req, success, failure)
		}
	}
}

// tlsHandshakeServiceDo performs the TLS handshake.
func tlsHandshakeServiceDo(
	ctx context.Context,
	req *TLSHandshakeRequest,
	success chan<- net.Conn,
	failure chan<- error,
) {
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	tc := req.Factory.NewClientConn(req.Conn, req.Config)
	err := tc.HandshakeContext(ctx)
	if err != nil {
		select {
		case failure <- err:
		case <-ctx.Done():
		}
		return
	}
	select {
	case success <- tc:
	case <-ctx.Done():
		tc.Close()
	}
}
