package bytecount

import (
	"context"
	"fmt"

	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
)

type Factory struct {
	objs bytecountObjects
	// after calling New(), the following are safe to use
	logger       *zap.SugaredLogger
	taStore      *store.TrafficAccountStore
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

func NewFactory(parentLogger *zap.SugaredLogger, taStore *store.TrafficAccountStore) (*Factory, error) {
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

	if taStore == nil {
		return nil, util.ErrStoreNotInited
	}

	return &Factory{
		logger:       logger,
		workQueue:    workQueue,
		nativeEndian: nativeEndian,
		taStore:      taStore,
	}, nil
}

func (bf *Factory) AddExportChannel(ctx context.Context, ec chan *store.TrafficReport) {
	log := bf.logger
	if ec == nil {
		log.Info("nil export channel added. is this correct?")
		return
	}
	bf.bytecountExportChannel = ec
}

func (bf *Factory) CleanUp(ctx context.Context, ipAddr string) error {
	return bf.taStore.DeleteTrafficAccount(ctx, ipAddr)
}
