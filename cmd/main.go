package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/caarlos0/env/v11"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/traffic"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/node/cilium_ccm"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/node/network_device"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/service"
	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	bpfcommon "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/common"
	ciliumbpffs "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/fs"
	zaplog "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log/zap"
	netlib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/net"
)

const (
	defaultConfigPath        = "/etc/sealos-nm-agent/config/config.yml"
	defaultTrafficExportAddr = "sealos-nm-traffic-exporter-service.sealos-nm-system.svc.cluster.local:8080"
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	mainCtx := context.Background()
	logger, err := zaplog.NewZap(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create the logger: %v\n", err)
		os.Exit(1)
	}
	globalConfig, err := initGlobalConfig()
	if err != nil {
		logger.Errorf("failed to initialize the global configuration: %v", err)
		return
	}
	if globalConfig == nil {
		logger.Infof("the global configuration is empty?")
		return
	}
	logger.Infof("print global config: %+v", globalConfig)
	var exportTrafficService modules.ExportTrafficService
	if globalConfig.NoExportingTraffic {
		ets, err := mock.NewDummyExportTrafficService(logger, globalConfig.DummyWatchedPodIP, globalConfig.DummyWatchedHostIP)
		if err != nil {
			logger.Errorf("failed to create a dummy export traffic service: %v", err)
			return
		}
		exportTrafficService = ets

	} else {
		etsConfig := service.NewExportTrafficServiceConfig()
		etsConfig.TrafficExporterAddr = defaultTrafficExportAddr
		etsConfig.MaxWorkerCount = globalConfig.ExportTrafficServiceWorkerCount
		etsParams := service.ExportTrafficServiceParams{
			ParentLogger:               logger,
			ExportTrafficServiceConfig: etsConfig,
		}
		ets, err := service.NewExportTrafficService(etsParams)
		if err != nil {
			logger.Errorf("failed to create the export traffic service: %v", err)
			return
		}
		if err := ets.Start(context.TODO()); err != nil {
			logger.Error(err)
			return
		}
		defer ets.Close()
		exportTrafficService = ets
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Error(err)
		return
	}
	tfConfig := modules.BPFTrafficFactoryConfig{
		ReaderMaxWorker:  5,
		HandlerMaxWorker: 5,
		UseCiliumCCM:     globalConfig.WatchCiliumEndpoint,
	}
	params := traffic.TrafficFactoryParams{
		ParentLogger:            logger,
		BPFTrafficFactoryConfig: tfConfig,
		ExportTrafficService:    exportTrafficService,
	}
	trafficFactory, err := traffic.NewTrafficFactory(params)
	if err != nil {
		logger.Error(err)
		return
	}
	trafficFactory.Start(context.TODO())
	defer trafficFactory.Close()

	// initialize and start the network device watcher
	ndwConfig := network_device.NewNetworkDeviceWatcherConfig()
	ndwConfig.WatchPodDevice = !globalConfig.WatchCiliumEndpoint
	nmNetLib := netlib.NewNMNetLib()
	ndwParams := network_device.NetworkDeviceWatcherParams{
		ParentLogger:               logger,
		NetworkDeviceWatcherConfig: ndwConfig,
		BPFTrafficFactory:          trafficFactory,
		NetLib:                     nmNetLib,
	}
	deviceWatcher, err := network_device.NewNetworkDeviceWatcher(ndwParams)
	if err != nil {
		logger.Error(err)
		return
	}
	if err := deviceWatcher.Start(mainCtx); err != nil {
		logger.Error(err)
		return
	}
	// initialize and start the cep watcher if WatchCiliumEndpoint is set to true
	cwConfig := cilium_ccm.NewCiliumCCMWatcherConfig()
	cwConfig.Enabled = globalConfig.WatchCiliumEndpoint
	ciliumBPFFS := ciliumbpffs.NewCiliumBPFFS(bpfcommon.DefaultCiliumTCRoot)
	cwParams := cilium_ccm.CiliumCCMWatcherParams{
		ParentLogger:           logger,
		CiliumCCMWatcherConfig: cwConfig,
		BPFTrafficFactory:      trafficFactory,
		CiliumBPFFS_:           ciliumBPFFS,
	}
	ccmWatcher, err := cilium_ccm.NewCiliumCCMWatcher(cwParams)
	if err != nil {
		logger.Error(err)
		return
	}
	if err := ccmWatcher.Start(mainCtx); err != nil {
		logger.Error(err)
		return
	}
	<-sigs
}

type GlobalConfig struct {
	NoExportingTraffic bool `env:"NO_EXPORTING_TRAFFIC"`
	// if this option is set to true, the agent will watch the cilium endpoints' custom call maps
	// instead of their lxc devices, which also means the agent will receive traffic events by
	// cilium tail-calling our programs via custom call maps
	// this feature requires using cilium as cni and enable custom call hook
	WatchCiliumEndpoint             bool   `env:"WATCH_CILIUM_ENDPOINT"`
	DummyWatchedPodIP               string `env:"DUMMY_WATCHED_POD_IP"`
	DummyWatchedHostIP              string `env:"DUMMY_WATCHED_HOST_IP"`
	TrafficEventHandlerWorkerCount  int    `env:"TRAFFIC_EVENT_HANDLER_WORKER_COUNT"`
	ExportTrafficServiceWorkerCount int    `env:"EXPORT_TRAFFIC_SERVICE_WORKER_COUNT"`
}

func NewGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		NoExportingTraffic:              false,
		WatchCiliumEndpoint:             false,
		DummyWatchedPodIP:               "",
		DummyWatchedHostIP:              "",
		TrafficEventHandlerWorkerCount:  5,
		ExportTrafficServiceWorkerCount: 5,
	}
}

func initGlobalConfig() (*GlobalConfig, error) {
	cfg := NewGlobalConfig()
	opts := env.Options{
		Prefix: "NM_AGENT_",
	}
	if err := env.ParseWithOptions(cfg, opts); err != nil {
		return nil, err
	}
	return cfg, nil
}
