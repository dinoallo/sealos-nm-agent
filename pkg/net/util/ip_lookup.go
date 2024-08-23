package util

import (
	"fmt"
	"net"
	"net/netip"
)

// GetOutboundV4AddrsInCIDR gets current v6 address used for outbound traffic
// by asking a non-local dns service provided by the user. If `include4In6`
// is set to true, it also returns the current v4 address' v6 expression
func GetOutboundV4AddrsInCIDR(externalDNSService string, include4In6 bool) ([]netip.Prefix, error) {
	conn, err := net.Dial("udp", externalDNSService)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	addr, ok := netip.AddrFromSlice(localAddr.IP)
	if !ok {
		return nil, fmt.Errorf("failed to convert the ip of the local address of type net.IP to type netip.Addr")
	}
	var prefixes []netip.Prefix
	if addr.Is4() {
		prefix := netip.PrefixFrom(addr, 32)
		prefixes = append(prefixes, prefix)
		if include4In6 {
			_4In6Addr := netip.AddrFrom16(addr.As16())
			prefix := netip.PrefixFrom(_4In6Addr, 128)
			prefixes = append(prefixes, prefix)
		}
	} else if addr.Is4In6() {
		if include4In6 {
			prefix := netip.PrefixFrom(addr, 128)
			prefixes = append(prefixes, prefix)
		}
		prefix := netip.PrefixFrom(addr.Unmap(), 32)
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// GetOutboundV6AddrsInCIDR gets current v6 address used for outbound traffic
// by asking a non-local dns service provided by the user.
func GetOutboundV6AddrsInCIDR(externalDNSService string) ([]netip.Prefix, error) {
	conn, err := net.Dial("udp", externalDNSService)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	addr, ok := netip.AddrFromSlice(localAddr.IP)
	if !ok {
		return nil, fmt.Errorf("failed to convert the ip of the local address of type net.IP to type netip.Addr")
	}
	var prefixes []netip.Prefix
	if addr.Is6() {
		prefix := netip.PrefixFrom(addr, 128)
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}
