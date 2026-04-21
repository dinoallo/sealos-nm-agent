package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/cleanup"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/mongo"
	loglib "github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	zaplog "github.com/dinoallo/sealos-networkmanager-agent/pkg/log/zap"
)

var (
	mainLogger   loglib.Logger
	globalConfig *conf.GlobalConfig

	ErrInitingGlobalConfig = errors.New("failed to init the global config")
	ErrStartingDB          = errors.New("failed to start the database")
	ErrCreatingCleanup     = errors.New("failed to create the cleanup service")
	ErrRunningCleanup      = errors.New("failed to run the cleanup service")
	ErrDBDisabled          = errors.New("database is disabled")
)

func main() {
	ctx := context.Background()

	logger, err := zaplog.NewZap(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create the logger: %v\n", err)
		os.Exit(1)
	}
	mainLogger = logger

	cfg, err := conf.InitGlobalConfig()
	if err != nil || cfg == nil {
		printErr(errors.Join(err, ErrInitingGlobalConfig))
		os.Exit(1)
	}
	globalConfig = cfg
	mainLogger.Debugf("print global config: %+v", globalConfig)

	if !globalConfig.DBConfig.Enabled {
		printErr(ErrDBDisabled)
		os.Exit(1)
	}

	mongoOpts := mongo.NewMongoOpts()
	mongodb, err := mongo.NewMongo(globalConfig.DBConfig.Uri, globalConfig.DBConfig.Name, mongoOpts)
	if err != nil {
		printErr(errors.Join(err, ErrStartingDB))
		os.Exit(1)
	}
	defer func() {
		if err := mongodb.Close(ctx); err != nil {
			printErr(err)
		}
	}()

	ts, err := store.NewTrafficStore(store.TrafficStoreParams{
		ParentLogger:       mainLogger,
		DB:                 mongodb,
		TrafficStoreConfig: globalConfig.TrafficStoreConfig,
	})
	if err != nil {
		printErr(errors.Join(err, ErrCreatingCleanup))
		os.Exit(1)
	}

	c, err := cleanup.NewTrafficCleanup(cleanup.TrafficCleanupParams{
		ParentLogger:       mainLogger,
		TrafficStore:       ts,
		TrafficStoreConfig: globalConfig.TrafficStoreConfig,
	})
	if err != nil {
		printErr(errors.Join(err, ErrCreatingCleanup))
		os.Exit(1)
	}

	if err := c.Run(ctx); err != nil {
		printErr(errors.Join(err, ErrRunningCleanup))
		os.Exit(1)
	}
}

func printErr(err error) {
	if mainLogger != nil {
		mainLogger.Errorf("%v", err)
		return
	}
	fmt.Fprintf(os.Stderr, "%v\n", err)
}
