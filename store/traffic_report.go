package store

import (
	"context"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"
	nanoid "github.com/matoous/go-nanoid/v2"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	TRAFFIC_REPORT_WORKER_COUNT = (2 << 10)
)

type TrafficReportStore struct {
	name           string
	logger         *zap.SugaredLogger
	manager        *StoreManager
	trafficReports chan *TrafficReport
	cache          *lru_expirable.LRU[string, TrafficReport]
}

func NewTrafficReportStore(baseLogger *zap.SugaredLogger) (*TrafficReportStore, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	trafficReports := make(chan *TrafficReport)
	return &TrafficReportStore{
		name:           "traffic_reports",
		logger:         baseLogger.With(zap.String("component", "traffic_account_store")),
		trafficReports: trafficReports,
	}, nil
}

func (s *TrafficReportStore) AddTrafficReport(ctx context.Context, report *TrafficReport) error {
	s.trafficReports <- report
	return nil
}

func (s *TrafficReportStore) processTrafficReport(ctx context.Context, report *TrafficReport) error {
	if report == nil {
		return util.ErrTrafficReportNotInited
	}
	if s.cache == nil {
		return util.ErrCacheNotInited
	}
	if id, err := nanoid.New(); err != nil {
		return err
	} else {
		s.cache.Add(id, *report)
	}
	return nil
}

func (s *TrafficReportStore) initCache(ctx context.Context) error {
	p := s.manager.ps
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	cache := lru_expirable.NewLRU[string, TrafficReport](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_EXPIRED_TIME)
	s.cache = cache
	return nil
}

func (s *TrafficReportStore) onEvicted(key string, value TrafficReport) {
	if s.manager == nil || s.logger == nil {
		return
	}
	logger := s.logger
	ps := s.manager.ps
	if ps != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
		defer cancel()
		if err := ps.insertOne(ctx, TRCollection, value); err != nil {
			logger.Errorf("unable to evicted the traffic account: %v", err)
		}
	} else {
		logger.Errorf("eviction failed: %v", util.ErrPersistentStorageNotInited)
		return
	}

}

func (s *TrafficReportStore) setManager(manager *StoreManager) error {
	if manager == nil {
		return util.ErrStoreManagerNotInited
	}
	s.manager = manager
	return nil
}

func (s *TrafficReportStore) getName() string {
	return s.name
}

func (s *TrafficReportStore) launch(ctx context.Context, eg *errgroup.Group) error {
	if s.manager == nil {
		return util.ErrStoreManagerNotInited
	}
	if s.manager.ps == nil {
		return util.ErrPersistentStorageNotInited
	}
	if found, err := s.manager.ps.findCollection(ctx, TRCollection); err != nil {
		return err
	} else if !found {
		metaField := TRAFFIC_REPORT_META_FIELD
		if err := s.manager.ps.createTSDB(ctx, TRCollection, TRAFFIC_REPORT_TIME_FIELD, &metaField); err != nil {
			return err
		}
	}
	for i := 0; i < TRAFFIC_REPORT_WORKER_COUNT; i++ {
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case report := <-s.trafficReports:
					if err := s.processTrafficReport(ctx, report); err != nil {
						return err
					}
				}
			}
		})
	}
	return nil

}
