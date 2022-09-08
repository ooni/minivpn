package obfs4

import (
	"fmt"
	"log"
	"net"
	"net/url"
)

// ProxyNode is a proxy node, that can be used to construct a proxy chain.
type ProxyNode struct {
	Addr     string
	Protocol string // obfs4 in this case
	url      *url.URL
	Values   url.Values // contains the cert and iat-mode parameters
	// base dialer to be passed to obfuscation dialer
	Dial DialFunc
}

// NewProxyNodeFromURI returns a configured proxy node. It accepts a string
// with all the parameters needed to establish a connection to the obfs4
// proxy, in the form "obfs4://<ip>:<port>?cert=<deadbeef>&iat-mode=<int>"
func NewProxyNodeFromURI(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ProxyNode{}, err
	}
	log.Printf("Using %s proxy at %s:%s", u.Scheme, u.Hostname(), u.Port())

	if u.Scheme != "obfs4" {
		return ProxyNode{}, fmt.Errorf("expected obfs4:// uri")
	}

	return ProxyNode{
		Protocol: u.Scheme,
		Addr:     net.JoinHostPort(u.Hostname(), u.Port()),
		url:      u,
		Values:   u.Query(),
	}, nil
}
