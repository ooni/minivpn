// Package reliabletransport implements the reliable transport module for OpenVPN.
// See [the official documentation](https://community.openvpn.net/openvpn/wiki/SecurityOverview) for a detail explanation
// of why this is needed, and how it relates to the requirements of the control channel.
// It is worth to mention that, even though the original need is to have a reliable control channel
// on top of UDP, this is also used when tunneling over TCP.
//
// A note about terminology: in this package, "receiver" is the moveUpWorker in the [reliabletransport.Service] (since it receives incoming packets), and
// "sender" is the moveDownWorker in the same service. The corresponding data structures lack mutexes because they are intended to be confined to a single
// goroutine (one for each worker), and they SHOULD ONLY communicate via message passing.
package reliabletransport
