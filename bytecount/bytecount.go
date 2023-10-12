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
	IPv4Egress  = BytecountMapType{s: "ipv4 egress", t: 2}
)

func (s *CountingServer) DumpCounter(in *counterpb.Counter, srv counterpb.CountingService_DumpCounterServer) error {
	eid := in.GetEndpointId()
	log.Printf("Received dumping request for endpoint_id: %v", eid)

	ipv4IngressBytecountPinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_ingress_bytecount_%05d", eid)
	ipv4EgressBytecountPinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_egress_bytecount_%05d", eid)
	pinPaths := []string{ipv4IngressBytecountPinPath, ipv4EgressBytecountPinPath}
	if flag, err := checkCounterMapExists(pinPaths); err == nil && flag == false {
		return util.ErrBPFMapNotExist
	} else if err != nil {
		log.Printf("unable to check if the counter exist")
		return util.ErrBPFMapFailedToCheck
	}

	var bytecountMapType BytecountMapType
	for t, pinPath := range pinPaths {
		log.Printf("bytecount map type: %d", t)
		switch t {
		case 0:
			bytecountMapType = IPv4Ingress
		case 1:
			bytecountMapType = IPv4Egress
		default:
			bytecountMapType = Unknown
		}
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			log.Printf("unable to load the %s bytecount map for the endpoint %5d", bytecountMapType.s, eid)
			return util.ErrBPFMapNotLoaded
		}
		defer m.Close()
		var entries = m.Iterate()
		var (
			key   uint32
			value uint64
		)
		for entries.Next(&key, &value) {
			dump := counterpb.CounterDump{EndpointId: eid, Bytes: value, Identity: key, Type: bytecountMapType.t}
			if err := srv.Send(&dump); err != nil {
				log.Printf("send error %v", err)
			}
		}

	}
	return nil
}

func (s *CountingServer) CreateCounter(ctx context.Context, in *counterpb.CreateCounterRequest) (*counterpb.Counter, error) {
	// get the endpoint id from the request
	eid := in.GetEndpointId()
	initValues := in.GetInitValues()
	t := in.GetType()
	var bytecountMapType BytecountMapType
	var bytecountPinPath string
	var bytecountMap *ebpf.Map
	var bytecountCustomHook *ebpf.Program
	var ccmKey uint32 // load the bytecount program

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
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Printf("unable to load the counter program to the kernel and assign it.")
		return nil, util.ErrBPFProgramNotLoaded
	}
	defer objs.Close()

	switch t {
	case 1:
		bytecountMapType = IPv4Ingress
		bytecountPinPath = BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_ingress_bytecount_%05d", eid)
		bytecountMap = objs.bpfMaps.Ipv4IngressBytecountMap
		bytecountCustomHook = objs.bpfPrograms.Ipv4IngressBytecountCustomHook
		ccmKey = 0
	case 2:
		bytecountMapType = IPv4Egress
		bytecountPinPath = BPF_FS_ROOT + fmt.Sprintf("tc/globals/ipv4_egress_bytecount_%05d", eid)
		bytecountMap = objs.bpfMaps.Ipv4EgressBytecountMap
		bytecountCustomHook = objs.bpfPrograms.Ipv4EgressBytecountCustomHook
		ccmKey = 1
	default:
		bytecountMapType = Unknown
	}
	if bytecountMapType == Unknown {
		return nil, util.ErrUnknownBytecountMapType
	}
	log.Printf("create %s counter for endpoint_id: %05d", bytecountMapType.s, eid)

	pinPaths := []string{bytecountPinPath}
	if flag, err := checkCounterMapExists(pinPaths); err == nil && flag {
		if err := os.Remove(bytecountPinPath); err != nil {
			log.Printf("unable to remove the stale %s counter map", bytecountMapType.s)
			return nil, util.ErrBPFMapNotRemoved
		} else if err != nil {
			log.Printf("unable to check if counter exist")
			return nil, util.ErrBPFMapFailedToCheck
		}
	}

	if !bytecountMap.IsPinned() {
		if err := bytecountMap.Pin(bytecountPinPath); err != nil {
			log.Printf("unable to pin the %s bytecount map: %s", bytecountMapType.s, err.Error())
			return nil, util.ErrBPFMapNotPinned
		}
	}
	for initKey, initValue := range initValues {
		if err := bytecountMap.Put(initKey, initValue); err != nil {
			log.Printf("unable to initialize the %s bytecount map for endpont %05d: %s", bytecountMapType.s, eid, err.Error())
			return nil, util.ErrBPFMapNotInitialized
		}
	}
	if err := ccm.Put(ccmKey, bytecountCustomHook); err != nil {
		log.Printf("unable to update the custom hook map for the endpoint %05d on %s: %s", eid, bytecountMapType.s, err.Error())
		return nil, util.ErrBPFMapNotUpdated
	}

	// return the counter id, which is the same for our endpoint
	counter := &counterpb.Counter{
		EndpointId: eid,
	}
	return counter, nil
}

func (s *CountingServer) RemoveCounter(ctx context.Context, in *counterpb.Counter) (*counterpb.Empty, error) {
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
				return &counterpb.Empty{}, util.ErrBPFMapNotRemoved
			}
		}
	} else if err != nil {
		log.Printf("unable to check if the counter exist")
		return &counterpb.Empty{}, util.ErrBPFMapFailedToCheck
	}

	return &counterpb.Empty{}, nil
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
