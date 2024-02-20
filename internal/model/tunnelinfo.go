package model

// TunnelInfo holds state about the VPN TunnelInfo that has longer duration than a
// given session. This information is gathered at different stages:
// - during the handshake (mtu).
// - after server pushes config options(ip, gw).
type TunnelInfo struct {
	// GW is the Route Gateway.
	GW string

	// IP is the assigned IP.
	IP string

	// MTU is the configured MTU pushed by the remote.
	MTU int

	// NetMask is the netmask configured on the TUN interface, pushed by the ifconfig command.
	NetMask string

	// PeerID is the peer-id assigned to us by the remote.
	PeerID int
}
