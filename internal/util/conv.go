package util

import (
	"encoding/binary"
	"net"
)

// TODO: implemented ipv6
func ToIP(_v4Addr uint32, _v6Addr []uint32, t int) net.IP {
	if t == 4 {
		return toIPv4(_v4Addr)
	} else if t == 6 {
		return toIPv6(_v6Addr)
	}
	return nil
}

func toIPv4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func toIPv6(nn []uint32) net.IP {
	/*
		ip := make(net.IP, 16)
		for i := 0; i < 8; i++ {
			binary.BigEndian.PutUint16(ip[i*2:i*2+2], nn[i])
		}
		return ip*/
	//TODO: implement me
	return nil
}
