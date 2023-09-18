package bytecount

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf bytecount.c -- -I../bpf/headers
import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"log"
	"os"
)

const (
	BPF_FS_ROOT = "/sys/fs/bpf/"
)

type CountingServer struct {
	counterpb.UnimplementedCountingServiceServer
}

type BytecountMapType struct {
	s string
	t uint32
}

var (
	Unknown     = BytecountMapType{s: "unknown type", t: 0}
	IPv4Ingress = BytecountMapType{s: "ipv4 ingress", t: 1}
	IPv4Engress = BytecountMapType{s: "ipv4 egress", t: 2}
)

func (s *CountingServer) DumpCounter(ctx context.Context, in *counterpb.Counter) (*counterpb.CounterDumps, error) {
	eid := in.GetEndpointId()
	log.Printf("Received dumping request for endpoint_id: %v", eid)

	ipv4IngressBytecountPinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_ingress_bytecount_%05d", eid)
	ipv4EgressBytecountPinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_egress_bytecount_%05d", eid)
	pinPaths := []string{ipv4IngressBytecountPinPath, ipv4EgressBytecountPinPath}
	if flag, err := checkCounterMapExists(pinPaths); err == nil && flag == false {
		// counter does not exist
		log.Printf("this counter doesn't exist, try to create one")
		_, counterCreateError := s.CreateCounter(ctx, &counterpb.NewCounter{EndpointId: eid})
		if counterCreateError != nil {
			log.Printf("unable to create counter before dumping it")
			return nil, counterCreateError
		}
	} else if err != nil {
		log.Printf("unable to check if the counter exist")
		return nil, util.ErrBPFMapFailedToCheck
	}

	var bytecountMapType BytecountMapType
	dumps := []*counterpb.Dump{}
	for t, pinPath := range pinPaths {
		log.Printf("bytecount map type: %d", t)
		switch t {
		case 0:
			bytecountMapType = IPv4Ingress
		case 1:
			bytecountMapType = IPv4Engress
		default:
			bytecountMapType = Unknown
		}
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			log.Printf("unable to load the %s bytecount map for the endpoint %5d", bytecountMapType.s, eid)
			return nil, util.ErrBPFMapNotLoaded
		}
		defer m.Close()
		var entries = m.Iterate()
		var (
			key   uint32
			value uint64
		)

		for entries.Next(&key, &value) {
			dump := counterpb.Dump{Bytes: value, Identity: key, Type: bytecountMapType.t}
			dumps = append(dumps, &dump)
		}

	}

	counterDumps := &counterpb.CounterDumps{
		EndpointId: eid,
		Dumps:      dumps,
	}

	return counterDumps, nil
}

func (s *CountingServer) CreateCounter(ctx context.Context, in *counterpb.NewCounter) (*counterpb.Counter, error) {
	// get the endpoint id from the request
	eid := in.GetEndpointId()
	log.Printf("Received create counter request for endpoint_id: %v", eid)

	// check and load the custom call map for this endpoint. if the ccm doesn't exist, (may due to the migration for cilium configuration, which leads to new endpoints have ccm while others don't)
	// we inform the caller by returning a special error
	ccmPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/cilium_calls_custom_%05d", eid)
	if _, err := os.Stat(ccmPath); errors.Is(err, os.ErrNotExist) {
		log.Printf("unable to find the custom hook map for the endpoint %05d", eid)
		return nil, util.ErrBPFCustomCallMapNotExist
	}
	ccm, err := ebpf.LoadPinnedMap(ccmPath, nil)

	if err != nil {
		log.Printf("unable to load the custom hook map for the endpoint %05d", eid)
		return nil, util.ErrBPFMapNotLoaded
	}
	defer ccm.Close()

	// load the bytecount program
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Printf("unable to load the counter program to the kernel and assign it.")
		return nil, util.ErrBPFProgramNotLoaded
	}
	defer objs.Close()

	// pin the bytecounter map for ipv4 ingress
	if !objs.bpfMaps.Ipv4IngressBytecountMap.IsPinned() {
		pinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_ingress_bytecount_%05d", eid)
		if err := objs.bpfMaps.Ipv4IngressBytecountMap.Pin(pinPath); err != nil {
			log.Printf("unable to pin the IPv4 ingress bytecounter map: %s", err.Error())
			return nil, util.ErrBPFMapNotPinned
		}
	}

	// pin the bytecounter map for ipv4 egress
	if !objs.bpfMaps.Ipv4EgressBytecountMap.IsPinned() {
		pinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_egress_bytecount_%05d", eid)
		if err := objs.bpfMaps.Ipv4EgressBytecountMap.Pin(pinPath); err != nil {
			log.Printf("unable to pin the IPv4 egress bytecounter map: %s", err.Error())
			return nil, util.ErrBPFMapNotPinned
		}
	}

	// update the IPv4 ingress map on the custom map
	if err := ccm.Put(uint32(0), objs.bpfPrograms.Ipv4IngressBytecountCustomHook); err != nil {
		log.Printf("unable to update the custom hook map for the endpoint %05d on IPv4 ingress", eid)
		return nil, util.ErrBPFMapNotUpdated
	}

	if err := ccm.Put(uint32(1), objs.bpfPrograms.Ipv4EgressBytecountCustomHook); err != nil {
		log.Printf("unable to update the custom hook map for the endpoint %05d on IPv4 egress", eid)
		return nil, util.ErrBPFMapNotUpdated
	}

	// return the counter id, which is the same for our endpoint
	counter := &counterpb.Counter{
		EndpointId: eid,
	}
	return counter, nil
}

func (s *CountingServer) RemoveCounter(ctx context.Context, in *counterpb.NewCounter) error {
	// get the endpoint id from the request
	eid := in.GetEndpointId()
	log.Printf("Received remove counter request for endpoint_id: %v", eid)

	ipv4IngressBytecountPinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_ingress_bytecount_%05d", eid)
	ipv4EgressBytecountPinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_egress_bytecount_%05d", eid)
	pinPaths := []string{ipv4IngressBytecountPinPath, ipv4EgressBytecountPinPath}

	if flag, err := checkCounterMapExists(pinPaths); err == nil && flag == true {
		for _, pinPath := range pinPaths {
			if counterRemoveError := removeCounterMap(pinPath); counterRemoveError != nil {
				log.Printf("unable to remove counter map %s for endpoint: %05d", pinPath, eid)
				return util.ErrBPFMapNotRemoved
			}
		}
	} else if err != nil {
		log.Printf("unable to check if the counter exist")
		return util.ErrBPFMapFailedToCheck
	}

	return nil
}

func checkCounterMapExists(pinPaths []string) (bool, error) {
	for _, pinPath := range pinPaths {
		if _, err := os.Stat(pinPath); errors.Is(err, os.ErrNotExist) {
			return false, nil
		} else if err != nil {
			return false, err
		}
	}
	return true, nil
}

func removeCounterMap(pinPath string) error {
	err := os.Remove(pinPath)
	return err
}
