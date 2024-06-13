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
	"github.com/dinoallo/sealos-networkmanager-agent/internal/node/network_device"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/service"
	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
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
	etsConfig := service.NewExportTrafficServiceConfig()
	etsConfig.TrafficExporterAddr = defaultTrafficExportAddr
	etsParams := service.ExportTrafficServiceParams{
		ParentLogger:               logger,
		ExportTrafficServiceConfig: etsConfig,
	}
	var exportTrafficService modules.ExportTrafficService
	if globalConfig.NoExportingTraffic {
		ets, err := mock.NewDummyExportTrafficService(logger, globalConfig.DummyWatchedPodIP, globalConfig.DummyWatchedHostIP)
		if err != nil {
			logger.Errorf("failed to create a dummy export traffic service: %v", err)
			return
		}
		exportTrafficService = ets

	} else {
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

	// initialize and start the bpf traffic event manager
	// drtsParams := mock.DummyRawTrafficStoreParams{
	// 	Logger: logger,
	// }
	// rawTrafficStore := mock.NewDummyRawTrafficStore(drtsParams)
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Error(err)
		return
	}
	ptemConfig := traffic.NewPodTrafficEventManagerConfig()
	ptemParams := traffic.PodTrafficEventManagerParams{
		ParentLogger:         logger,
		Config:               ptemConfig,
		ExportTrafficService: exportTrafficService,
	}
	podTrafficEventManager, err := traffic.NewPodTrafficEventManager(ptemParams)
	if err != nil {
		logger.Error(err)
		return
	}
	if err := podTrafficEventManager.Start(mainCtx); err != nil {
		logger.Error(err)
		return
	}
	defer podTrafficEventManager.Close()
	htemConfig := traffic.NewHostTrafficEventManagerConfig()
	htemParams := traffic.HostTrafficEventManagerParams{
		ParentLogger:         logger,
		Config:               htemConfig,
		ExportTrafficService: exportTrafficService,
	}
	hostTrafficEventManager, err := traffic.NewHostTrafficEventManager(htemParams)
	if err != nil {
		logger.Error(err)
		return
	}
	if err := hostTrafficEventManager.Start(mainCtx); err != nil {
		logger.Error(err)
		return
	}
	defer hostTrafficEventManager.Close()
	// initialize and start the network device watcher
	ndwConfig := network_device.NewNetworkDeviceWatcherConfig()
	officialNetLib := netlib.NewGoNetLib()
	ndwParams := network_device.NetworkDeviceWatcherParams{
		ParentLogger:               logger,
		NetworkDeviceWatcherConfig: ndwConfig,
		BPFHostTrafficModule:       hostTrafficEventManager,
		BPFPodTrafficModule:        podTrafficEventManager,
		NetLib:                     officialNetLib,
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
	<-sigs
}

type GlobalConfig struct {
	NoExportingTraffic bool   `env:"NO_EXPORTING_TRAFFIC"`
	DummyWatchedPodIP  string `env:"DUMMY_WATCHED_POD_IP"`
	DummyWatchedHostIP string `env:"DUMMY_WATCHED_HOST_IP"`
}

func NewGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		//TODO: support v6 dns service
		NoExportingTraffic: false,
		DummyWatchedPodIP:  "",
		DummyWatchedHostIP: "",
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
