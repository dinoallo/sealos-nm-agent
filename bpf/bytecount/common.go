package bytecount

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

const (
	BPF_FS_ROOT            = "/sys/fs/bpf"
	CILIUM_TC_ROOT         = BPF_FS_ROOT + "/tc/globals"
	TRAFFIC_CONSUMER_COUNT = (2 << 9)
	PERF_BUFFER_SIZE       = (32 << 10) // 32KB
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
