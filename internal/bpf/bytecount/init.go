package bytecount

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/perf"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"

	"golang.org/x/sync/errgroup"
)

func (bf *BytecountFactory) startReader(ctx context.Context) error {
	readerEg := errgroup.Group{}
	readerEg.SetLimit(bf.cfg.MaxReaderCount)
	log := bf.logger
	v4EgressEventReader, err := perf.NewReader(bf.objs.EgressTrafficEvents, bf.cfg.PerfBufferSize)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			readerEg.Go(
				func() error {
					// read egress traffic
					if err := bf.readTraffic(ctx, v4EgressEventReader, 1); err != nil {
						log.Errorf("unable to read traffic: %v", err)
					}
					return nil
				})
		}
	}
}

func (bf *BytecountFactory) startProcessor(ctx context.Context) error {
	processorEg := errgroup.Group{}
	processorEg.SetLimit(bf.cfg.MaxProcessorCount)
	log := bf.logger
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			processorEg.Go(
				func() error {
					if err := bf.processTraffic(ctx); err != nil {
						log.Errorf("unable to process traffic: %v", err)
					}
					return nil
				})
		}
	}
}

func (bf *BytecountFactory) stop(ctx context.Context) error {
	return bf.objs.Close()
}

func (bf *BytecountFactory) initObjs(ctx context.Context) error {
	log := bf.logger

	bf.objs = bytecountObjects{}
	// loading the bpf programs
	log.Infof("loading bpf program objects...")
	if err := loadBytecountObjects(&bf.objs, nil); err != nil {
		log.Infof("unable to load the counter program to the kernel and assign it.")
		return util.ErrBPFProgramNotLoaded
	}
	// IPv4Ingress.ClsProgram = bf.objs.IngressBytecountCustomHook
	// IPv4Egress.ClsProgram = bf.objs.EgressBytecountCustomHook
	bf.v4IngressCounter = Counter{
		TypeStr:                "ipv4 ingress",
		TypeInt:                0,
		PinPathTemplate:        fmt.Sprintf("%s/ipv4_ingress_bytecount_prog_", CILIUM_TC_ROOT) + "%05d",
		CustomCallPathTemplate: fmt.Sprintf("%s/cilium_calls_custom_", CILIUM_TC_ROOT) + "%05d",
		CustomCallMapKey:       0,
		ClsProgram:             bf.objs.IngressBytecountCustomHook,
	}
	bf.v4EgressCounter = Counter{
		TypeStr:                "ipv4 egress",
		TypeInt:                1,
		PinPathTemplate:        fmt.Sprintf("%s/ipv4_egress_bytecount_prog", CILIUM_TC_ROOT) + "_%05d",
		CustomCallPathTemplate: fmt.Sprintf("%s/cilium_calls_custom_", CILIUM_TC_ROOT) + "%05d",
		CustomCallMapKey:       1,
		ClsProgram:             bf.objs.EgressBytecountCustomHook,
	}

	return nil
}

func (bf *BytecountFactory) initCounter(ctx context.Context) error {
	var ceps []structs.CiliumEndpoint
	logger := bf.logger
	s := bf.param.CES
	logger.Infof("recovering counters...")
	// get all the endpoints from the database and recover the counters
	err := s.GetAllCEPs(ctx, &ceps)
	if err != nil {
		return err
	}
	for _, cep := range ceps {
		err = bf.createCounter(ctx, cep.EndpointID, consts.TRAFFIC_DIR_V4_EGRESS)
		if err == util.ErrBPFCustomCallMapNotExist {
			if err := s.RemoveCEP(ctx, cep.EndpointID); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			logger.Infof("counter %v recovered", cep.EndpointID)
		}
	}
	return nil
}
