package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/traffic"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/node/network_device"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/service"
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
	etsConfig := service.NewExportTrafficServiceConfig()
	etsConfig.TrafficExporterAddr = defaultTrafficExportAddr
	etsParams := service.ExportTrafficServiceParams{
		ParentLogger:               logger,
		ExportTrafficServiceConfig: etsConfig,
	}
	exportTrafficService, err := service.NewExportTrafficService(etsParams)
	if err != nil {
		logger.Errorf("failed to create the export traffic service: %v", err)
	}
	if err := exportTrafficService.Start(context.TODO()); err != nil {
		logger.Error(err)
		return
	}
	defer exportTrafficService.Close()

	// initialize and start the bpf traffic event manager
	// drtsParams := mock.DummyRawTrafficStoreParams{
	// 	Logger: logger,
	// }
	// rawTrafficStore := mock.NewDummyRawTrafficStore(drtsParams)
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Error(err)
		return
	}
	temConfig := traffic.NewTrafficEventManagerConfig()
	temParams := traffic.TrafficEventManagerParams{
		ParentLogger:         logger,
		Config:               temConfig,
		ExportTrafficService: exportTrafficService,
	}
	trafficEventManager, err := traffic.NewTrafficEventManager(temParams)
	if err != nil {
		logger.Error(err)
		return
	}
	if err := trafficEventManager.Start(mainCtx); err != nil {
		logger.Error(err)
		return
	}
	defer trafficEventManager.Close()
	// initialize and start the network device watcher
	ndwConfig := network_device.NewNetworkDeviceWatcherConfig()
	officialNetLib := netlib.NewGoNetLib()
	ndwParams := network_device.NetworkDeviceWatcherParams{
		ParentLogger:               logger,
		NetworkDeviceWatcherConfig: ndwConfig,
		BPFTrafficModule:           trafficEventManager,
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
