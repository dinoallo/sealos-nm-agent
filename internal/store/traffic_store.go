package store

import (
	"context"
	"errors"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/cache"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"golang.org/x/sync/errgroup"
)

type TrafficStoreParams struct {
	ParentLogger log.Logger
	db.DB
	conf.TrafficStoreConfig
}

type TrafficStore struct {
	log.Logger
	podTrafficCache  *cache.Cache[*PodTrafficAccount, structs.PodTraffic]
	hostTrafficCache *cache.Cache[*HostTrafficAccount, structs.HostTraffic]
	TrafficStoreParams
}

func NewTrafficStore(params TrafficStoreParams) (*TrafficStore, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_store")
	if err != nil {
		return nil, err
	}
	defaultCacheConfig := cache.NewCacheConfig()
	defaultCacheConfig.EntryTTL = params.CacheEntryTTL
	defaultCacheConfig.ExpiredEntrySize = params.CacheExpiredEntrySize
	defaultCacheConfig.EntrySize = params.CacheEntrySize
	podTrafficCache, err := cache.NewCache[*PodTrafficAccount, structs.PodTraffic](defaultCacheConfig)
	if err != nil {
		return nil, err
	}
	hostTrafficCache, err := cache.NewCache[*HostTrafficAccount, structs.HostTraffic](defaultCacheConfig)
	if err != nil {
		return nil, err
	}
	return &TrafficStore{
		Logger:             logger,
		podTrafficCache:    podTrafficCache,
		hostTrafficCache:   hostTrafficCache,
		TrafficStoreParams: params,
	}, nil
}

func (s *TrafficStore) Start(ctx context.Context) error {
	// create the collection for pod traffic if it doesn't exist
	if err := s.createCollIfNotExists(ctx, s.PodTrafficColl, s.UseTimeSeriesColl); err != nil {
		return err
	}
	// create the collection for host traffic if it doesn't exist
	if err := s.createCollIfNotExists(ctx, s.HostTrafficColl, s.UseTimeSeriesColl); err != nil {
		return err
	}
	s.startFlushingForPodTraffic(ctx)
	s.startFlushingForHostTraffic(ctx)
	return nil
}

func (s *TrafficStore) UpdatePodTraffic(ctx context.Context, hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error {
	if err := s.updatePodMetric(hash, meta, metric); err != nil {
		return err
	}
	return nil
}

func (s *TrafficStore) UpdateHostTraffic(ctx context.Context, hash string, meta structs.HostTrafficMeta, metric structs.HostTrafficMetric) error {
	if err := s.updateHostMetric(hash, meta, metric); err != nil {
		return err
	}
	return nil
}

// make this more general
func (s *TrafficStore) updatePodMetric(hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error {
	newAcct := NewPodTrafficAccount(hash, meta)
	acct, err := s.podTrafficCache.LoadOrStore(hash, newAcct)
	if err != nil {
		return err
	}
	acct.PodMetric.RecvBytes.Add(metric.RecvBytes)
	acct.PodMetric.SentBytes.Add(metric.SentBytes)
	return nil
}

func (s *TrafficStore) updateHostMetric(hash string, meta structs.HostTrafficMeta, metric structs.HostTrafficMetric) error {
	newAcct := NewHostTrafficAccount(hash, meta)
	acct, err := s.hostTrafficCache.LoadOrStore(hash, newAcct)
	if err != nil {
		return err
	}
	acct.HostMetric.RecvBytes.Add(metric.RecvBytes)
	acct.HostMetric.SentBytes.Add(metric.SentBytes)
	return nil
}

func (s *TrafficStore) startFlushingForPodTraffic(ctx context.Context) {
	wg := &errgroup.Group{}
	wg.SetLimit(s.MaxWorkerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					if err := s.flushPodTraffic(ctx, s.podTrafficCache, s.PodTrafficColl); err != nil {
						return err
					}
					return nil
				})
			}
		}
	}()
}

func (s *TrafficStore) startFlushingForHostTraffic(ctx context.Context) {
	wg := &errgroup.Group{}
	wg.SetLimit(s.MaxWorkerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					if err := s.flushHostTraffic(ctx, s.hostTrafficCache, s.HostTrafficColl); err != nil {
						return err
					}
					return nil
				})
			}
		}
	}()
}

func (s *TrafficStore) createCollIfNotExists(ctx context.Context, collName string, useTimeSeries bool) error {
	// If the collection already exists, we don't need to do anything
	// If useTimeSeries is true, we will create a time series collection, otherwise we will create a normal collection
	if useTimeSeries {
		timeSeriesOpts := db.TimeSeriesOpts{
			TimeField:   structs.PodTrafficTimeField,
			MetaField:   structs.PodTrafficMetaField,
			ExpireAfter: convertToSeconds(s.DBExpireAfter),
		}
		if err := s.CreateTimeSeriesColl(ctx, collName, timeSeriesOpts); err != nil {
			if err == db.ErrCollectionAlreadyExists {
				s.Infof("the collection %v already exists, so we are not going to do anything", collName)
			} else {
				s.Errorf("failed to create the collection %v: %v", collName, err)
				return err
			}
		}
	} else {
		createCollOpts := db.CreateCollOpts{
			ExpireAfter: convertToSeconds(s.DBExpireAfter),
		}
		if err := s.CreateColl(ctx, collName, createCollOpts); err != nil {
			if err == db.ErrCollectionAlreadyExists {
				s.Infof("the collection %v already exists, so we are not going to do anything", collName)
			} else {
				s.Errorf("failed to create the collection %v: %v", collName, err)
				return err
			}
		}
	}
	return nil
}

//TODO: merge the following flushing functions

func (s *TrafficStore) flushPodTraffic(ctx context.Context, c *cache.Cache[*PodTrafficAccount, structs.PodTraffic], coll string) error {
	batch, err := c.GetBatchExpiredEntries(ctx, s.GetBatchTimeout, s.BatchSize)
	if err != nil {
		if err == cache.ErrTimeoutGettingExpiredEntries {

		} else {
			return err
		}
	}
	if len(batch) == 0 {
		return nil
	}
	_ctx, cancel := context.WithTimeout(ctx, s.FlushTimeout)
	defer cancel()
	var items []any
	for _, item := range batch {
		items = append(items, item)
	}
	db := s.DB
	if err := db.Insert(_ctx, coll, items); err != nil {
		return err
	}
	return nil
}

func (s *TrafficStore) flushHostTraffic(ctx context.Context, c *cache.Cache[*HostTrafficAccount, structs.HostTraffic], coll string) error {
	batch, err := c.GetBatchExpiredEntries(ctx, s.GetBatchTimeout, s.BatchSize)
	if err != nil {
		if err == cache.ErrTimeoutGettingExpiredEntries {

		} else {
			return err
		}
	}
	if len(batch) == 0 {
		return nil
	}
	_ctx, cancel := context.WithTimeout(ctx, s.FlushTimeout)
	defer cancel()
	var items []any
	for _, item := range batch {
		items = append(items, item)
	}
	db := s.DB
	if err := db.Insert(_ctx, coll, items); err != nil {
		return err
	}
	return nil
}

func (s *TrafficStore) CleanupExpiredTraffic(ctx context.Context) error {
	if s.UseTimeSeriesColl || s.DBExpireAfter <= 0 {
		return nil
	}

	expireBefore := time.Now().Add(-s.DBExpireAfter)
	var errs []error

	if s.PodTrafficColl != "" {
		deleted, err := s.DB.DeleteExpiredBefore(ctx, s.PodTrafficColl, structs.PodTrafficTimeField, expireBefore)
		if err != nil {
			s.Errorf("failed to cleanup expired pod traffic from collection %v: %v", s.PodTrafficColl, err)
			errs = append(errs, err)
		} else {
			s.Infof("cleaned up %d expired pod traffic records from collection %v before %v", deleted, s.PodTrafficColl, expireBefore.Format(time.RFC3339))
		}
	}

	if s.HostTrafficColl != "" {
		deleted, err := s.DB.DeleteExpiredBefore(ctx, s.HostTrafficColl, structs.HostTrafficTimeField, expireBefore)
		if err != nil {
			s.Errorf("failed to cleanup expired host traffic from collection %v: %v", s.HostTrafficColl, err)
			errs = append(errs, err)
		} else {
			s.Infof("cleaned up %d expired host traffic records from collection %v before %v", deleted, s.HostTrafficColl, expireBefore.Format(time.RFC3339))
		}
	}

	return errors.Join(errs...)
}

func convertToSeconds(d time.Duration) int64 {
	return int64(d.Seconds())
}
