//
// Package vpn contains the API to create an OpenVPN client that can connect to
// a remote OpenVPN endpoint and provide you with a tunnel where to send packets.
//
// The recommended way to use this package is to use the TunDialer
// constructors, that gives you a way to transparently Dial() and get TCP or
// UDP sockets over a virtual gVisor interface, that uses the VPN tunnel as an
// underlying transport. For examples, see the `proxy' implementation in the
// `extras` package.
//
// If you need to write raw packets to the tunnel instead, you can construct
// and use a `Client` object directly. `Client` is an implementer of the
// `net.Conn` interface. You need to `Start()` the Client before you can Read
// or Write packets to it. An example of this can be found in the `extras/ping`
// package.
//
// Reads and Writes to the Client tunnel object are
// actually reading and writing to the initialized Data channel of the Client.
// Any incoming packet while reading that is not an OpenVPN data packet will be
// dispatched accordingly.
package vpn
