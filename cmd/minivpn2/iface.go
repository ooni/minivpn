package main

import (
	"fmt"
	"net"
)

func getInterfaceByIP(ipAddr string) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.String() == ipAddr {
					return &iface, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("interface with IP %s not found", ipAddr)
}
