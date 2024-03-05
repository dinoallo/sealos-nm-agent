package cmd

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/bytecount"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/service"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/cilium_endpoint"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/traffic_record"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func main() {

	// parse flags
	var devMode = flag.Bool("devMode", false, "run in development mode")
	flag.Parse()

	var dbUri string = os.Getenv(conf.DB_URI_ENV)

	// Initialize the logger
	logger, err := util.GetLogger(*devMode)
	if err != nil {
		return
	}
	logger.Info("the logger is ready...")

	// Init logger for main
	log := logger.With(zap.String("component", "main"))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)

	// Init configuration
	mainConf, err := conf.InitConfig(logger, *devMode)
	if err != nil {
		log.Fatal(err)
	}

	// Allow the current process to lock memory for eBPF resources.
	// only need this if the kernel version < 5.11
	// requires CAP_SYS_RESOURCE on kernel < 5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mainEg := errgroup.Group{}
	// init persistent store
	pp := persistent.PersistentParam{
		ParentLogger: logger,
		DBURI:        dbUri,
	}
	p := persistent.NewPersistentInterface(pp, *mainConf.PersistentStorageConfig)
	p.Launch(ctx, &mainEg)
	defer p.Stop(ctx)

	// init cilium endpoint store
	cep := cilium_endpoint.CiliumEndpointStoreParam{
		ParentLogger: logger,
		P:            p,
	}
	ces := cilium_endpoint.NewCiliumEndpointStoreInterface(cep, *mainConf.CiliumEndpointStoreConfig)
	ces.Launch(ctx, &mainEg)

	// init traffic record store
	trsp := traffic_record.TrafficRecordStoreParam{
		ParentLogger: logger,
		P:            p,
	}
	trs := traffic_record.NewTrafficRecordStoreInterface(trsp, *mainConf.TrafficRecordStoreConfig)
	trs.Launch(ctx, &mainEg)

	// init bytecount factory
	bfp := bytecount.BytecountFactoryParam{
		ParentLogger: logger,
		TRS:          trs,
		CES:          ces,
	}
	bf := bytecount.NewBytecountFactoryInterface(bfp, *mainConf.BytecountFactoryConfig)
	bf.Launch(ctx, &mainEg)
	defer bf.Stop(ctx)

	// Init Services
	tsp := service.TrafficServiceParam{
		ParentLogger: logger,
		BF:           bf,
		CES:          ces,
	}
	ts, err := service.NewTrafficService(tsp, *mainConf.TrafficServiceConfig)
	if err != nil {
		log.Fatalf("failed to create new traffic service: %v", err)
		return
	}
	ts.Launch(ctx, &mainEg)
	defer ts.Stop(ctx)
	<-sig
	cancel()
	close(sig)
	if err := mainEg.Wait(); err != nil {
		log.Errorf("%v", err)
	}
}
