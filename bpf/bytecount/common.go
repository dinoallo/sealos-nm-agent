package bytecount

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

const (
	BPF_FS_ROOT      = "/sys/fs/bpf"
	CILIUM_TC_ROOT   = BPF_FS_ROOT + "/tc/globals"
	PERF_BUFFER_SIZE = (64 << 10) // 64KB

	BYTECOUNT_FACTORY_MAX_READER_COUNT      = (1 << 0)
	BYTECOUNT_FACTORY_MAX_PROCESSOR_COUNT   = (1 << 3)
	BYTECOUNT_FACTORY_TRAFFIC_MAX_QUEUE_LEN = (1 << 20)
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
