package bytecount

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
)

const (
	BPF_FS_ROOT            = "/sys/fs/bpf"
	CILIUM_TC_ROOT         = BPF_FS_ROOT + "/tc/globals"
	TRAFFIC_CONSUMER_COUNT = 5
	PERF_BUFFER_SIZE       = (32 << 10) // 32KB
)

type Factory struct {
	objs bytecountObjects
	// after calling New(), the following are safe to use
	logger       *zap.SugaredLogger
	store        *store.Store
	workQueue    chan Traffic
	nativeEndian binary.ByteOrder
	// the following are not safe to use, please check if it's nil
	// before accessing it
	bytecountExportChannel chan *store.TrafficReport
}

type Traffic struct {
	trafficRecord *perf.Record
	trafficType   uint32
}

type Counter struct {
	TypeStr string
	TypeInt uint32
	// the bpf program this counter is associated with
	ClsProgram *ebpf.Program
	// the path template to pin the bpf program
	PinPathTemplate        string
	CustomCallPathTemplate string
	CustomCallMapKey       uint32
}

var (
	IPv4Ingress = Counter{
		TypeStr:                "ipv4 ingress",
		TypeInt:                0,
		PinPathTemplate:        fmt.Sprintf("%s/ipv4_ingress_bytecount_prog_", CILIUM_TC_ROOT) + "%05d",
		CustomCallPathTemplate: fmt.Sprintf("%s/cilium_calls_custom_", CILIUM_TC_ROOT) + "%05d",
		CustomCallMapKey:       0,
	}
	IPv4Egress = Counter{
		TypeStr:                "ipv4 egress",
		TypeInt:                1,
		PinPathTemplate:        fmt.Sprintf("%s/ipv4_egress_bytecount_prog", CILIUM_TC_ROOT) + "_%05d",
		CustomCallPathTemplate: fmt.Sprintf("%s/cilium_calls_custom_", CILIUM_TC_ROOT) + "%05d",
		CustomCallMapKey:       1,
	}
)

func NewFactory(parentLogger *zap.SugaredLogger, st *store.Store) (*Factory, error) {
	// init logger
	if parentLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	logger := parentLogger.With("component", "bytecount_factory")
	// init workqueue
	workQueue := make(chan Traffic)
	// get host endian
	var nativeEndian binary.ByteOrder
	if e, err := getHostEndian(); err != nil {
		return nil, err
	} else {
		nativeEndian = e
	}

	if st == nil {
		return nil, util.ErrStoreNotInited
	}

	return &Factory{
		logger:       logger,
		workQueue:    workQueue,
		nativeEndian: nativeEndian,
		store:        st,
	}, nil
}

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
