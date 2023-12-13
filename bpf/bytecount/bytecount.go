package bytecount

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"

	"bytes"
	"encoding/binary"

	"golang.org/x/sys/unix"

	"os"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
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

func (bf *Factory) Launch(ctx context.Context) error {
	log := bf.logger
	bf.objs = bytecountObjects{}

	log.Infof("loading bpf program objects...")
	if err := loadBytecountObjects(&bf.objs, nil); err != nil {
		log.Infof("unable to load the counter program to the kernel and assign it.")
		return util.ErrBPFProgramNotLoaded
	}
	go func(ctx context.Context) {
		defer bf.objs.Close()
		<-ctx.Done()
	}(ctx)
	IPv4Ingress.ClsProgram = bf.objs.IngressBytecountCustomHook
	IPv4Egress.ClsProgram = bf.objs.EgressBytecountCustomHook

	log.Infof("launching traffic event reader...")
	go bf.readTraffic(ctx, IPv4Egress.TypeInt)
	for i := 0; i < TRAFFIC_CONSUMER_COUNT; i++ {
		log.Infof("launching traffic event consumer...")
		go bf.processTraffic(ctx)
	}
	log.Infof("traffic counting factory launched")
	return nil
}

func (bf *Factory) readTraffic(ctx context.Context, t uint32) {
	log := bf.logger
	objs := bf.objs
	var eventArray *ebpf.Map
	switch t {
	case IPv4Ingress.TypeInt:
		eventArray = objs.IngressTrafficEvents
	case IPv4Egress.TypeInt:
		eventArray = objs.EgressTrafficEvents
	default:
		return
	}
	er, err := perf.NewReader(eventArray, PERF_BUFFER_SIZE)
	if err != nil {
		log.Errorf("failed to create a new reader")
		return
	}
	go func(ctx context.Context) {
		defer er.Close()
		<-ctx.Done()
	}(ctx)

	for {
		rec, err := er.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Infof("the perf event channel is closed")
				return
			} else {
				log.Infof("reading from perf event reader: %v", err)
				continue
			}
		}
		if rec.LostSamples != 0 {
			log.Infof("perf event ring buffer full, dropped %d samples", rec.LostSamples)
			continue
		}
		tr := Traffic{
			trafficRecord: &rec,
			trafficType:   t,
		}
		bf.workQueue <- tr
	}
}

func (bf *Factory) processTraffic(ctx context.Context) {
	log := bf.logger

	for {
		select {
		case <-ctx.Done():
			break
		case traffic := <-bf.workQueue:
			var event bytecountTrafficEventT
			if traffic.trafficRecord != nil {
				if err := binary.Read(bytes.NewBuffer(traffic.trafficRecord.RawSample), bf.nativeEndian, &event); err != nil {
					log.Infof("Failed to decode received data: %+v", err)
					continue
				}
				t := traffic.trafficType
				if err := bf.submit(ctx, &event, t); err != nil {
					log.Infof("Failed to submit the traffic report: %+v", err)
					continue
				}
			}
		}
	}
}

func (bf *Factory) submit(ctx context.Context, event *bytecountTrafficEventT, t uint32) error {
	var dir store.TrafficDirection
	__srcIP := make([]uint32, 4)
	__dstIP := make([]uint32, 4)
	var srcPort uint32
	var dstPort uint32
	switch t {
	case IPv4Ingress.TypeInt:
		dir = store.V4Ingress
		__srcIP[0] = event.DstIp4
		__dstIP[0] = event.SrcIp4
		srcPort = uint32(event.DstPort)
		dstPort = event.SrcPort
	case IPv4Egress.TypeInt:
		dir = store.V4Egress
		__srcIP[0] = event.SrcIp4
		__dstIP[0] = event.DstIp4
		srcPort = event.SrcPort
		dstPort = uint32(event.DstPort)
	default:
		return nil
	}

	if event.Family == unix.AF_INET || event.Family == unix.AF_INET6 {
		report := &store.TrafficReport{
			Dir:       dir,
			Protocol:  event.Protocol,
			SrcIP:     util.ToIP(__srcIP[0], nil, 4),
			DstIP:     util.ToIP(__dstIP[0], nil, 4),
			SrcPort:   srcPort,
			DstPort:   dstPort,
			DataBytes: event.Len,
			Identity:  identity.NumericIdentity(event.Identity),
		}
		// log.Debugf("protocol: %v; %v bytes sent", event.Protocol, event.Len)
		bf.store.AddTrafficReport(ctx, report)
	}
	return nil
}

func (bf *Factory) CreateCounter(ctx context.Context, eid int64, c Counter) error {

	log := bf.logger.With(zap.Int64("endpoint", eid), zap.String("direction", c.TypeStr))
	// check and load the custom call map for this endpoint. if the ccm doesn't exist, (may due to the migration for cilium configuration, which leads to new endpoints have ccm while others don't)
	// we inform the caller by returning a special error
	ccmPath := fmt.Sprintf(c.CustomCallPathTemplate, eid)
	if _, err := os.Stat(ccmPath); errors.Is(err, os.ErrNotExist) {
		log.Errorf("unable to find the custom hook map for the endpoint: %v", err)
		return util.ErrBPFCustomCallMapNotExist
	}
	ccm, err := ebpf.LoadPinnedMap(ccmPath, nil)

	if err != nil {
		log.Errorf("unable to load the custom hook map for the endpoint: %v", err)
		return util.ErrBPFMapNotLoaded
	}
	defer ccm.Close()

	prog := c.ClsProgram
	if err := ccm.Put(c.CustomCallMapKey, prog); err != nil {
		log.Errorf("unable to update the custom hook map for the endpoint: %v", err)
		return util.ErrBPFMapNotUpdated
	}

	// log.Debugf("counter created")
	return nil
}

func (bf *Factory) CleanUp(ctx context.Context, ipAddr string) error {
	return bf.store.DeleteTrafficAccount(ctx, ipAddr)
}

func (bf *Factory) Subscribe(ctx context.Context, addr string, port uint32) error {
	return bf.store.AddSubscribedPort(ctx, addr, port)
}

func (bf *Factory) Unsubscribe(ctx context.Context, addr string, port uint32) error {
	return bf.store.RemoveSubscribedPort(ctx, addr, port)
}

func (bf *Factory) DumpTraffic(ctx context.Context, addr string, tag string, reset bool) (uint64, uint64, error) {
	if p, err := bf.store.DumpTraffic(ctx, addr, tag, reset); err != nil {
		return 0, 0, err
	} else {
		return p.SentBytes, p.RecvBytes, nil
	}

}

func (bf *Factory) RemoveCounter(ctx context.Context, eid int64, c Counter) error {
	pinPath := fmt.Sprintf(c.PinPathTemplate, eid)
	log := bf.logger.With(zap.Int64("endpoint", eid), zap.String("direction", c.TypeStr))
	if flag, err := checkCounterExists(pinPath); err == nil && flag == true {
		if counterRemoveError := removeCounterMap(pinPath); counterRemoveError != nil {
			log.Errorf("unable to remove counter program for the endpoint: %v", err)
			return util.ErrBPFMapNotRemoved
		}

	} else if err != nil {
		log.Errorf("unable to check if the counter exist: %v", err)
		return util.ErrBPFMapFailedToCheck
	}

	log.Debugf("counter removed")
	return nil
}

func checkCounterExists(pinPath string) (bool, error) {
	if _, err := os.Stat(pinPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func removeCounterMap(pinPath string) error {
	err := os.Remove(pinPath)
	return err
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
