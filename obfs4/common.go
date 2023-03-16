package obfs4

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
)

var (
	// errBadProxyURI indicates a malformed URI for an obfs4 endpoint
	errBadProxyURI = errors.New("bad obfs4 uri")
)

// ProxyNode is a proxy node, that can be used to construct a proxy chain.
type ProxyNode struct {
	Addr     string
	Protocol string // obfs4 in this case
	url      *url.URL
	Values   url.Values // contains the cert and iat-mode parameters
	// base dialer to be passed to obfuscation dialer
	UnderlyingDialer simpleDialer
}

// NewProxyNodeFromURI returns a configured proxy node. It accepts a string
// with all the parameters needed to establish a connection to the obfs4
// proxy, in the form "obfs4://<ip>:<port>?cert=<deadbeef>&iat-mode=<int>"
func NewProxyNodeFromURI(uri string) (*ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return &ProxyNode{}, fmt.Errorf("%w: %v", errBadProxyURI, err)
	}
	if u.Scheme != "obfs4" {
		log.Println("Invalid URI for obfs4")
		return &ProxyNode{}, fmt.Errorf("%w: %s", errBadProxyURI, "expected obfs4:// scheme")
	}
	if u.Port() == "" {
		log.Println("Empty port for obfs4")
		return &ProxyNode{}, fmt.Errorf("%w: %s", errBadProxyURI, "missing port")
	}
	if u.Hostname() == "" {
		log.Println("Empty hostname for obfs4")
		return &ProxyNode{}, fmt.Errorf("%w: %s", errBadProxyURI, "missing hostname")
	}
	log.Printf("Using %s proxy at %s:%s", u.Scheme, u.Hostname(), u.Port())

	return &ProxyNode{
		Protocol: u.Scheme,
		Addr:     net.JoinHostPort(u.Hostname(), u.Port()),
		url:      u,
		Values:   u.Query(),
	}, nil
}
