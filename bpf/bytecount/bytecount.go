package bytecount

import (
	"context"
	"fmt"
	"net"
	"strings"

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
	name         string
	logger       *zap.SugaredLogger
	cepStore     *store.CiliumEndpointStore
	trStore      *store.TrafficMonitorStore
	workQueue    chan Traffic
	nativeEndian binary.ByteOrder
	ipAddrs      []string

	// the following are not safe to use, please check if it's nil
	// before accessing it
	bytecountExportChannel chan *store.TrafficReport
	rawTrafficChannel      chan *Traffic
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

func NewFactory(parentLogger *zap.SugaredLogger, trStore *store.TrafficMonitorStore, cepStore *store.CiliumEndpointStore) (*Factory, error) {
	// init logger
	if parentLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	name := "traffic_factory"
	logger := parentLogger.With("component", name)
	// init workqueue
	workQueue := make(chan Traffic)
	// get host endian
	var nativeEndian binary.ByteOrder
	if e, err := getHostEndian(); err != nil {
		return nil, err
	} else {
		nativeEndian = e
	}

	if trStore == nil || cepStore == nil {
		return nil, util.ErrStoreNotInited
	}

	var ipAddrs []string
	if ifs, err := net.Interfaces(); err != nil {
		return nil, err
	} else {
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
			if addrs, err := infa.Addrs(); err != nil {
				return nil, err
			} else {
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
							logger.Infof("address: %v", ipnet.IP.String())
							ipAddrs = append(ipAddrs, ipnet.IP.String())
						}
					}
				}
			}
		}
	}

	return &Factory{
		logger:            logger,
		workQueue:         workQueue,
		nativeEndian:      nativeEndian,
		trStore:           trStore,
		cepStore:          cepStore,
		ipAddrs:           ipAddrs,
		rawTrafficChannel: make(chan *Traffic, BYTECOUNT_FACTORY_TRAFFIC_MAX_QUEUE_LEN),
	}, nil
}

func (bf *Factory) GetName() string {
	return bf.name
}

func (bf *Factory) AddExportChannel(ctx context.Context, ec chan *store.TrafficReport) {
	log := bf.logger
	if ec == nil {
		log.Info("nil export channel added. is this correct?")
		return
	}
	bf.bytecountExportChannel = ec
}
