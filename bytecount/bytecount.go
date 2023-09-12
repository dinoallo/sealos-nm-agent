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

func (s *CountingServer) DumpCounter(ctx context.Context, in *counterpb.Counter) (*counterpb.CounterDumps, error) {
	eid := in.GetEndpointId()
	log.Printf("Received dumping request for endpoint_id: %v", eid)

	pinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/bytecount_%05d", eid)
	if _, err := os.Stat(pinPath); errors.Is(err, os.ErrNotExist) {
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
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		log.Printf("unable to load the bytecount map for the endpoint %5d", eid)
		return nil, util.ErrBPFMapNotLoaded
	}
	defer m.Close()
	var entries = m.Iterate()
	var (
		key   uint32
		value uint64
	)

	dumps := []*counterpb.Dump{}

	for entries.Next(&key, &value) {
		dump := counterpb.Dump{Bytes: value, Identity: key}
		dumps = append(dumps, &dump)
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

	if !objs.bpfMaps.BytecountMap.IsPinned() {
		pinPath := BPF_FS_ROOT + fmt.Sprintf("tc/globals/bytecount_%05d", eid)
		if err := objs.bpfMaps.BytecountMap.Pin(pinPath); err != nil {
			log.Printf("unable to pin the counter program: %s", err.Error())
			return nil, util.ErrBPFProgramNotPinned
		}
	}

	// update the IPv4 ingress map on the custom map
	if err := ccm.Put(uint32(0), objs.bpfPrograms.CustomHook); err != nil {
		log.Printf("unable to update the custom hook map for the endpoint %05d on IPv4 ingress", eid)
		return nil, util.ErrBPFMapNotUpdated
	}

	// return the counter id, which is the same for our endpoint
	counter := &counterpb.Counter{
		EndpointId: eid,
	}
	return counter, nil
}
