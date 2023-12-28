package bytecount

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
)

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

func (bf *Factory) initCounter(ctx context.Context) error {
	return nil
}
