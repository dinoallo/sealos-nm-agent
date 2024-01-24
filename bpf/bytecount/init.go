package bytecount

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/dinoallo/sealos-networkmanager-agent/util"

	"golang.org/x/sync/errgroup"
)

func (bf *Factory) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	log := bf.logger
	bf.objs = bytecountObjects{}

	// loading the bpf programs
	log.Infof("loading bpf program objects...")
	if err := loadBytecountObjects(&bf.objs, nil); err != nil {
		log.Infof("unable to load the counter program to the kernel and assign it.")
		return util.ErrBPFProgramNotLoaded
	}
	IPv4Ingress.ClsProgram = bf.objs.IngressBytecountCustomHook
	IPv4Egress.ClsProgram = bf.objs.EgressBytecountCustomHook

	// recover the counters
	log.Infof("recovering the counters...")
	if err := bf.initCounter(ctx); err != nil {
		return err
	}

	log.Infof("launching traffic event reader...")
	mainEg.Go(func() error {
		workerEg := errgroup.Group{}
		workerEg.SetLimit(1)
		go func() {
			for {
				workerEg.Go(
					func() error {
						return bf.readTraffic(ctx, IPv4Egress.TypeInt)
					})
			}
		}()
		for {
			if err := workerEg.Wait(); err != nil {
				log.Errorf("unable to read traffic: %v", err)
			}
		}
	})
	go bf.readTraffic(ctx, IPv4Egress.TypeInt)
	log.Infof("traffic counting factory launched")
	return nil
}

func (bf *Factory) Stop(ctx context.Context) error {
	return bf.objs.Close()
}

func (bf *Factory) initCounter(ctx context.Context) error {
	var ceps []store.CiliumEndpoint
	s := bf.cepStore
	logger := bf.logger
	if logger == nil {
		return util.ErrLoggerNotInited
	}
	if s == nil {
		return util.ErrStoreNotInited
	}
	if found, err := s.GetAll(ctx, &ceps); err != nil {
		return err
	} else if found {
		for _, cep := range ceps {
			node := s.GetCurrentNode()
			if cep.Node != node {
				continue
			}
			if err := bf.CreateCounter(ctx, cep.EndpointID, IPv4Egress); err != nil {
				if err == util.ErrBPFCustomCallMapNotExist {
					// stale endpoint status
					if err := s.Remove(ctx, cep.EndpointID); err != nil {
						return err
					}
				} else {
					return err
				}
			} else {
				logger.Infof("counter %v recovered", cep.EndpointID)
			}
		}
	}
	return nil
}
