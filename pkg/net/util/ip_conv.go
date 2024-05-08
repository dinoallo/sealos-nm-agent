package util

import (
	"encoding/binary"
	"net"
	"net/netip"
)

func ToIP(_v4Addr uint32, _v6Addr []uint32, t int) (netip.Addr, bool) {
	if t == 4 {
		return toIPv4(_v4Addr)
	} else if t == 6 {
		return toIPv6(_v6Addr)
	}
	return netip.Addr{}, false
}

// TODO: use native endian
func toIPv4(nn uint32) (netip.Addr, bool) {
	ip := make([]byte, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, nn)
	return netip.AddrFromSlice(ip)
}

func toIPv6(nn []uint32) (netip.Addr, bool) {
	var ip []byte
	for i := 0; i < 4; i++ {
		_ip := make([]byte, net.IPv4len)
		binary.LittleEndian.PutUint32(_ip, nn[i])
		ip = append(ip, _ip...)
	}
	return netip.AddrFromSlice(ip)
}
