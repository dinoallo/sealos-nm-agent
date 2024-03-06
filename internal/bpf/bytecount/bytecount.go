package bytecount

import (
	//"fmt"

	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/cilium_endpoint"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/traffic_record"
	"go.uber.org/zap"
)

type BytecountFactoryParam struct {
	TRS          *traffic_record.TrafficRecordStoreInterface
	CES          *cilium_endpoint.CiliumEndpointStoreInterface
	ParentLogger *zap.SugaredLogger
}

type BytecountFactory struct {
	objs              bytecountObjects
	name              string
	logger            *zap.SugaredLogger
	workQueue         chan Traffic
	nativeEndian      binary.ByteOrder
	ipAddrs           []string
	param             BytecountFactoryParam
	rawTrafficChannel chan *Traffic
	cfg               conf.BytecountFactoryConfig

	v4IngressCounter Counter
	v4EgressCounter  Counter
}

type Traffic struct {
	r *perf.Record
	d consts.TrafficDirection
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

func newBytecountFactory(p BytecountFactoryParam, cfg conf.BytecountFactoryConfig) *BytecountFactory {
	name := "bytecount_factory"
	logger := p.ParentLogger.With("component", name)
	workQueue := make(chan Traffic)
	return &BytecountFactory{
		logger:            logger,
		workQueue:         workQueue,
		param:             p,
		cfg:               cfg,
		rawTrafficChannel: make(chan *Traffic, cfg.MaxTrafficQueueLen),
	}
}

func (f *BytecountFactory) setIPAddrs() error {
	ipAddrs, err := getHostIPAddrs()
	if err != nil {
		return err
	}
	f.ipAddrs = ipAddrs
	return nil
}

func (f *BytecountFactory) setNativeEndian() error {
	var nativeEndian binary.ByteOrder
	if e, err := getHostEndian(); err != nil {
		return err
	} else {
		nativeEndian = e
	}
	f.nativeEndian = nativeEndian
	return nil
}
