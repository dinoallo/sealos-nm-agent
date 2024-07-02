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

type PodTrafficStoreParams struct {
	db.DB
	conf.PodTrafficStoreConfig
}

type PodTrafficStore struct {
	defaultCache *cache.Cache[*PodTrafficAccount, structs.PodTraffic]
	PodTrafficStoreParams
}

func NewPodTrafficStore(params PodTrafficStoreParams) (*PodTrafficStore, error) {
	defaultCacheConfig := cache.NewCacheConfig()
	defaultCacheConfig.EntryTTL = params.CacheEntryTTL
	defaultCacheConfig.ExpiredEntrySize = params.CacheExpiredEntrySize
	defaultCacheConfig.EntrySize = params.CacheEntrySize
	defaultCache, err := cache.NewCache[*PodTrafficAccount, structs.PodTraffic](defaultCacheConfig)
	if err != nil {
		return nil, err
	}
	return &PodTrafficStore{
		defaultCache:          defaultCache,
		PodTrafficStoreParams: params,
	}, nil
}

func (s *PodTrafficStore) Start(ctx context.Context) error {
	log.Printf("try to create a time series collection: %v", s.DefaultColl)
	timeSeriesOpts := common.TimeSeriesOpts{
		TimeField:   structs.PodTrafficTimeField,
		MetaField:   structs.PodTrafficMetaField,
		ExpireAfter: 129600, // TODO: make this configurable
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

func (s *PodTrafficStore) Update(ctx context.Context, hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error {
	if err := s.updateMetric(hash, meta, metric); err != nil {
		return err
	}
	return nil
}

// make this more general
func (s *PodTrafficStore) updateMetric(hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error {
	newAcct := NewPodTrafficAccount(hash, meta)
	acct, err := s.defaultCache.LoadOrStore(hash, newAcct)
	if err != nil {
		return err
	}
	acct.PodMetric.RecvBytes.Add(metric.RecvBytes)
	acct.PodMetric.SentBytes.Add(metric.SentBytes)
	return nil
}

func (s *PodTrafficStore) flush(ctx context.Context, c *cache.Cache[*PodTrafficAccount, structs.PodTraffic], coll string) error {
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
