package bytecount

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"

	"bytes"
	"encoding/binary"
	"golang.org/x/sys/unix"

	"os"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
)

const (
	BPF_FS_ROOT    = "/sys/fs/bpf"
	CILIUM_TC_ROOT = BPF_FS_ROOT + "/tc/globals"
)

type Factory struct {
	objs   bytecountObjects
	Logger *zap.SugaredLogger
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
	go func() {
		log := s.Logger
		er, err := perf.NewReader(s.objs.EgressTrafficEvents, 32*1024)
		if err != nil {
			log.Infof("failed to create a new reader")
			return
		}
		for {
			if err := s.processTraffic(er, 8); err != nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}()
	go func(ctx context.Context) {
		defer s.objs.Close()
		<-ctx.Done()
	}(ctx)
	log.Infof("counting server launched")
	return nil
}

func (s *Factory) processTraffic(er *perf.Reader, consumerCount int) error {
	log := s.Logger
	for i := 0; i < consumerCount; i++ {
		go func() {
			rec, err := er.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Infof("the perf event channel is closed")
				} else {
					log.Infof("reading from perf event reader: %v", err)
				}
				return
			}
			if rec.LostSamples != 0 {
				log.Infof("perf event ring buffer full, dropped %d samples", rec.LostSamples)
				return
			}
			var event bytecountTrafficEventT
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
				log.Infof("Failed to decode received data: %+v", err)
				return
			}

			if event.Family != unix.AF_INET {
				log.Debugf("unsupported socket family type")
				return
			}
			srcIp4 := toIPv4(event.SrcIp4)
			dstIp4 := toIPv4(event.DstIp4)
			log.Debugf("%v:%v => %v:%v; %v bytes sent", srcIp4, event.SrcPort, dstIp4, event.DstPort, event.Len)
			// log.Debugf("family used: %v; %v bytes sent", event.Protocol, event.Len)
		}()
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

	log.Debugf("counter created")
	return nil
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

func toIPv4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}
