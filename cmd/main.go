package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/traffic"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/node/network_device"
	raw_traffic "github.com/dinoallo/sealos-networkmanager-agent/internal/traffic"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/db/mongo"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/host"
	zaplog "github.com/dinoallo/sealos-networkmanager-library/pkg/log/zap"
	netlib "github.com/dinoallo/sealos-networkmanager-library/pkg/net"
)

const (
	defaultConfigPath = "/etc/sealos-nm-agent/config/config.yml"
)

func main() {
	// read the configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = defaultConfigPath
	}
	globalConfig, err := conf.ReadGlobalConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read the global configuration: %v\n", err)
		return
	}
	// check if the agent is configured to run in the debug mode
	var debugMode bool = false
	if globalConfig.DebugUserConfig.Enabled {
		debugMode = true
		conf.PrintGlobalConfig()
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	mainCtx := context.Background()
	logger, err := zaplog.NewZap(debugMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create the logger: %v\n", err)
		os.Exit(1)
	}
	// set up the network address
	srcIP, err := host.GetInterfaceIPAddr(globalConfig.NetworkDevice, globalConfig.PreferredAddressVersion)
	if err != nil {
		logger.Error("failed to get an address for the agent: %v", err)
		return
	} else if srcIP == "" {
		logger.Error("there is no available address for this device")
		return
	}
	// set up the database
	dbURI := os.Getenv("DB_URI")
	opts := mongo.MongoOpts{
		DBURI:             dbURI,
		DBName:            "sealos-networkmanager",
		ConnectionTimeout: 5 * time.Second,
		MaxPoolSize:       1,
		Logger:            logger,
		SrcIP:             srcIP,
		SrcPort:           globalConfig.Port,
	}
	db, err := mongo.NewMongo(opts)
	if err != nil {
		logger.Error(err)
		return
	}
	defer db.Close(context.TODO())
	// initialize and start the raw traffic handler
	rthConfig := globalConfig.ParseRawTrafficStoreConfig()
	rthParams := raw_traffic.RawTrafficHandlerParams{
		DB:                      db,
		ParentLogger:            logger,
		RawTrafficHandlerConfig: rthConfig,
	}
	rawTrafficStore, err := raw_traffic.NewRawTrafficHandler(rthParams)
	if err != nil {
		logger.Error(err)
		return
	}
	if err := rawTrafficStore.Start(mainCtx); err != nil {
		logger.Error(err)
		return
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
	temConfig := traffic.NewTrafficEventManagerConfig()
	temParams := traffic.TrafficEventManagerParams{
		ParentLogger:    logger,
		Config:          temConfig,
		RawTrafficStore: rawTrafficStore,
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
