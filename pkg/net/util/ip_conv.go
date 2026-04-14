package util

import (
	"encoding/binary"
	"net"
	"net/netip"
	"unsafe"
)

func ToIP(_v4Addr uint32, _v6Addr []uint32, t int) (netip.Addr, bool) {
	if t == 4 {
		return toIPv4(_v4Addr)
	} else if t == 6 {
		return toIPv6(_v6Addr)
	}
	return netip.Addr{}, false
}

func hostEndian() binary.ByteOrder {
	var i uint16 = 0x0102
	b := *(*[2]byte)(unsafe.Pointer(&i))
	if b[0] == 0x02 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// toIPv4 converts a host-endian uint32 into an IP address.
// Callers must pass the IPv4 integer in host byte order.
func toIPv4(nn uint32) (netip.Addr, bool) {
	ip := make([]byte, net.IPv4len)
	hostEndian().PutUint32(ip, nn)
	return netip.AddrFromSlice(ip)
}

// toIPv6 converts four host-endian uint32 words into an IPv6 address.
// Callers must pass each IPv6 word in host byte order.
func toIPv6(nn []uint32) (netip.Addr, bool) {
	var ip []byte
	order := hostEndian()
	for i := 0; i < 4; i++ {
		_ip := make([]byte, net.IPv4len)
		order.PutUint32(_ip, nn[i])
		ip = append(ip, _ip...)
	}
	return netip.AddrFromSlice(ip)
}
