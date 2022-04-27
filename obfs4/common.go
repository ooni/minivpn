package obfs4

import (
	"fmt"
	"log"
	"net"
	"net/url"
)

// Node is a proxy node, that can be used to construct a proxy chain.
type Node struct {
	Addr     string     // ag: I'm guessing this is used like ip:port
	Host     string     // ... but then this is redundant
	Protocol string     // obfs4 in this case
	url      *url.URL   // url
	Values   url.Values // contains the cert and iat-mode parameters
	//Transport string     // this only makes sense if/when we do use different transporters for obfs4. for the time being this can be removed, or perhaps denoted as "raw"
}

// NewNodeNewNodeFromURI returns a configured proxy node. It accepts a string with all the parameters
// needed to establish a connection to the obfs4 proxy, in the form:
// obfs4://<ip>:<port>?cert=<deadbeef>&iat-mode=<int>
func NewNodeFromURI(uri string) (Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return Node{}, err
	}
	log.Printf("Using %s proxy at %s:%s", u.Scheme, u.Hostname(), u.Port())
	// q, err := url.ParseQuery(u.RawQuery)
	// log.Println("cert:", url.QueryEscape(q["cert"][0]))

	if u.Scheme != "obfs4" {
		return Node{}, fmt.Errorf("expected obfs4:// uri")
	}

	return Node{
		Protocol: u.Scheme,
		Addr:     net.JoinHostPort(u.Hostname(), u.Port()),
		Host:     u.Hostname(),
		url:      u,
		Values:   u.Query(),
	}, nil
}
