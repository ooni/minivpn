// Package reliabletransport implements the reliable transport module for OpenVPN.
// See [the official documentation](https://community.openvpn.net/openvpn/wiki/SecurityOverview) for a detailed explanation
// of why this is needed, and how it relates to the requirements of the control channel.
// It is worth to mention that, even though the original need is to have a reliable control channel
// on top of UDP, this is also used when tunneling over TCP.
package reliabletransport
