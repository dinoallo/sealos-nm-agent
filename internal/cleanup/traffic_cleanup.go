package cleanup

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
)

type TrafficCleanupParams struct {
	ParentLogger log.Logger
	modules.TrafficStore
	conf.TrafficStoreConfig
}

type TrafficCleanup struct {
	log.Logger
	TrafficCleanupParams
}

func NewTrafficCleanup(params TrafficCleanupParams) (*TrafficCleanup, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_cleanup")
	if err != nil {
		return nil, err
	}
	return &TrafficCleanup{
		Logger:               logger,
		TrafficCleanupParams: params,
	}, nil
}

func (c *TrafficCleanup) Run(ctx context.Context) error {
	if c.UseTimeSeriesColl {
		c.Infof("skip traffic cleanup because time series collections handle expiration automatically")
		return nil
	}
	if c.DBExpireAfter <= 0 {
		c.Infof("skip traffic cleanup because DBExpireAfter is not positive")
		return nil
	}

	runCtx, cancel := context.WithTimeout(ctx, c.FlushTimeout)
	defer cancel()

	if err := c.TrafficStore.CleanupExpiredTraffic(runCtx); err != nil {
		c.Errorf("failed to cleanup expired traffic: %v", err)
		return err
	}
	return nil
}
