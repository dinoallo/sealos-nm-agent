package bytecount

import (
	"context"
	"errors"
	"fmt"
	"net"
	// "time"

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
	BPF_FS_ROOT    = "/sys/fs/bpf"
	CILIUM_TC_ROOT = BPF_FS_ROOT + "/tc/globals"
)

type Factory struct {
	objs   bytecountObjects
	Logger *zap.SugaredLogger
	Store  *store.Store
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

func (s *Factory) Launch(ctx context.Context) error {

	log := s.Logger
	s.objs = bytecountObjects{}
	if err := loadBytecountObjects(&s.objs, nil); err != nil {
		log.Infof("unable to load the counter program to the kernel and assign it.")
		return util.ErrBPFProgramNotLoaded
	}
	IPv4Ingress.ClsProgram = s.objs.IngressBytecountCustomHook
	IPv4Egress.ClsProgram = s.objs.EgressBytecountCustomHook
	go s.processTraffic(ctx, IPv4Egress.TypeInt, 32)
	go func(ctx context.Context) {
		defer s.objs.Close()
		<-ctx.Done()
	}(ctx)
	log.Infof("counting server launched")
	return nil
}

func (bf *Factory) processTraffic(ctx context.Context, t uint32, consumerCount int) {
	log := bf.Logger
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
	er, err := perf.NewReader(eventArray, 32*1024)
	if err != nil {
		log.Errorf("failed to create a new reader")
		return
	}
	for i := 0; i < consumerCount; i++ {
		log.Infof("perf event buffer consumer %v launched", i)
		go func() {
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
				var event bytecountTrafficEventT
				if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
					log.Infof("Failed to decode received data: %+v", err)
					continue
				}
				if err := bf.submit(ctx, &event, t); err != nil {
					log.Infof("Failed to submit the traffic report: %+v", err)
					continue
				}
			}
			// log.Debugf("family used: %v; %v bytes sent", event.Protocol, event.Len)
		}()
	}
	go func(ctx context.Context) {
		defer er.Close()
		<-ctx.Done()
	}(ctx)
	return
}

func (bf *Factory) submit(ctx context.Context, event *bytecountTrafficEventT, t uint32) error {
	log := bf.Logger

	var dir store.TrafficDirection
	__localIP := make([]uint32, 4)
	__remoteIP := make([]uint32, 4)
	var localPort uint32
	var remotePort uint32
	switch t {
	case IPv4Ingress.TypeInt:
		dir = store.V4Ingress
		__localIP[0] = event.DstIp4
		__remoteIP[0] = event.SrcIp4
		localPort = uint32(event.DstPort)
		remotePort = event.SrcPort
	case IPv4Egress.TypeInt:
		dir = store.V4Egress
		__localIP[0] = event.SrcIp4
		__remoteIP[0] = event.DstIp4
		localPort = event.SrcPort
		remotePort = uint32(event.DstPort)
	default:
		return nil
	}

	if event.Family == unix.AF_INET {
		report := &store.TrafficReport{
			Dir:        dir,
			Protocol:   event.Protocol,
			LocalIP:    toIP(__localIP[0], nil, 4),
			RemoteIP:   toIP(__remoteIP[0], nil, 4),
			LocalPort:  localPort,
			RemotePort: remotePort,
			DataBytes:  event.Len,
			Identity:   identity.NumericIdentity(event.Identity),
		}
		// log.Debugf("protocol: %v; %v bytes sent", event.Protocol, event.Len)
		log.Debugf("protocol: %v; identity: %v; %v => %v, %v bytes sent;", report.Protocol, report.Identity, report.LocalIP, report.RemoteIP, report.DataBytes)
		bf.Store.AddTrafficReport(ctx, report)
	}
	return nil
}

func (bf *Factory) CreateCounter(ctx context.Context, eid int64, c Counter) error {

	log := bf.Logger.With(zap.Int64("endpoint", eid), zap.String("direction", c.TypeStr))
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
	if bf.Store == nil {
		// the store is not initialized
		return nil
	}
	return bf.Store.DeleteTrafficAccount(ctx, ipAddr)
}

func (bf *Factory) RemoveCounter(ctx context.Context, eid int64, c Counter) error {
	pinPath := fmt.Sprintf(c.PinPathTemplate, eid)
	log := bf.Logger.With(zap.Int64("endpoint", eid), zap.String("direction", c.TypeStr))
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

// TODO: implemented ipv6
func toIP(_v4Addr uint32, _v6Addr []uint32, t int) net.IP {
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
