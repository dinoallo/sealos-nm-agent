package store

import (
	"context"
	"log"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/cache"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/db"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/db/common"
	"golang.org/x/sync/errgroup"
)

type HostTrafficStoreParams struct {
	db.DB
	conf.HostTrafficStoreConfig
}

type HostTrafficStore struct {
	defaultCache *cache.Cache[*HostTrafficAccount, structs.HostTraffic]
	HostTrafficStoreParams
}

func NewHostTrafficStore(params HostTrafficStoreParams) (*HostTrafficStore, error) {
	defaultCacheConfig := cache.NewCacheConfig()
	defaultCacheConfig.EntryTTL = params.CacheEntryTTL
	defaultCacheConfig.ExpiredEntrySize = params.CacheExpiredEntrySize
	defaultCacheConfig.EntrySize = params.CacheEntrySize
	defaultCache, err := cache.NewCache[*HostTrafficAccount, structs.HostTraffic](defaultCacheConfig)
	if err != nil {
		return nil, err
	}
	return &HostTrafficStore{
		defaultCache:           defaultCache,
		HostTrafficStoreParams: params,
	}, nil
}

func (s *HostTrafficStore) Start(ctx context.Context) error {
	log.Printf("try to create a time series collection: %v", s.DefaultColl)
	timeSeriesOpts := common.TimeSeriesOpts{
		TimeField:   structs.HostTrafficTimeField,
		MetaField:   structs.HostTrafficMetaField,
		ExpireAfter: 1800, // TODO: make this configurable
	}
	if err := s.CreateTimeSeriesColl(ctx, s.DefaultColl, timeSeriesOpts); err != nil {
		if err == common.ErrCollectionAlreadyExists {
			log.Printf("the collection %v already exists, so we are not going to do anything", s.DefaultColl)
		} else {
			log.Printf("failed to create a time series collection: %v", err)
			return err
		}
	}
	wg := &errgroup.Group{}
	wg.SetLimit(s.MaxWorkerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					if err := s.flush(ctx, s.defaultCache, s.DefaultColl); err != nil {
						return err
					}
					return nil
				})
			}
		}
	}()
	return nil
}

func (s *HostTrafficStore) Update(ctx context.Context, hash string, meta structs.HostTrafficMeta, metric structs.HostTrafficMetric) error {
	if err := s.updateMetric(hash, meta, metric); err != nil {
		return err
	}
	return nil
}

// make this more general
func (s *HostTrafficStore) updateMetric(hash string, meta structs.HostTrafficMeta, metric structs.HostTrafficMetric) error {
	newAcct := NewHostTrafficAccount(hash, meta)
	acct, err := s.defaultCache.LoadOrStore(hash, newAcct)
	if err != nil {
		return err
	}
	acct.HostMetric.RecvBytes.Add(metric.RecvBytes)
	acct.HostMetric.SentBytes.Add(metric.SentBytes)
	return nil
}

func (s *HostTrafficStore) flush(ctx context.Context, c *cache.Cache[*HostTrafficAccount, structs.HostTraffic], coll string) error {
	batch, err := c.GetBatchExpiredEntries(ctx, s.GetBatchTimeout, s.BatchSize)
	if err != nil {
		if err == cache.ErrTimeoutGettingExpiredEntries {

		} else {
			return err
		}
	}
	if len(batch) < 0 {
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
