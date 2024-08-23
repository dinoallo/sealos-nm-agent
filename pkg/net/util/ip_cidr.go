package util

import (
	"net/netip"
)

func InNetwork(prefix, addr string) (bool, error) {
	network, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false, err
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false, err
	}
	b := network.Contains(ip)
	return b, nil
}
