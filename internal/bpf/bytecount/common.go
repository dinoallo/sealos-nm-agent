package bytecount

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unsafe"
)

const (
	BPF_FS_ROOT    = "/sys/fs/bpf"
	CILIUM_TC_ROOT = BPF_FS_ROOT + "/tc/globals"
)

func getHostEndian() (binary.ByteOrder, error) {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		return binary.LittleEndian, nil
	case [2]byte{0xAB, 0xCD}:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("could not determine native endianness")
	}
}

func getHostIPAddrs() ([]string, error) {
	var ipAddrs []string
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ifsToIgnore := []string{"en"}
	for _, infa := range ifs {
		ignoreInfa := false
		for _, prefix := range ifsToIgnore {
			if strings.HasPrefix(infa.Name, prefix) {
				ignoreInfa = true
				break
			}
		}
		if !ignoreInfa {
			continue
		}
		addrs, err := infa.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
					ipAddrs = append(ipAddrs, ipnet.IP.String())
				}
			}
		}
	}
	return ipAddrs, nil
}
