package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
)

type Convertable[V2 any] interface {
	GetHash() string
	ConvertToData() []*V2
}

type CacheConfig struct {
	// ristretto.Config
	EntryTTL         time.Duration
	ExpiredEntrySize int
	EntrySize        int
	MetricEnabled    bool
}

func NewCacheConfig() CacheConfig {
	return CacheConfig{
		// Config: ristretto.Config{
		// 	NumCounters:        1e7,
		// 	MaxCost:            1 << 30,
		// 	BufferItems:        64,
		// 	Metrics:            false,
		// 	IgnoreInternalCost: false,
		// },
		EntryTTL:         300 * time.Second,
		ExpiredEntrySize: 1e4,
		EntrySize:        1e6,
		MetricEnabled:    false,
	}
}

// func readRistrettoConfig(cfg conf.CacheConfig) ristretto.Config {
// 	return ristretto.Config{
// 		NumCounters: int64(cfg.CacheNumCounters),
// 		MaxCost:     int64(cfg.CacheMaxCost),
// 		BufferItems: int64(cfg.CacheBufferItems),
// 		Metrics:     cfg.CacheMetrics,
// 	}
// }

// func ReadCacheConfig(cfg conf.CacheConfig) CacheConfig {
// 	cacheConfig := NewCacheConfig()
// 	rConfig := readRistrettoConfig(cfg)
// 	cacheConfig.RistrettoConfig = rConfig
// 	cacheConfig.EntryTTL = time.Second * time.Duration(cfg.CacheFlushingPeriod)
// 	cacheConfig.ExpiredEntriesSize = cfg.CacheWaitingToFlushQueueSize
// 	return cacheConfig
// }

type Cache[V1 Convertable[V2], V2 any] struct {
	cfg            CacheConfig
	expirableCache *ristretto.Cache
	expiredEntries chan *V2
	entries        *sync.Map
}

func NewCache[V1 Convertable[V2], V2 any](cfg CacheConfig) (*Cache[V1, V2], error) {
	entries := &sync.Map{}
	expiredEntries := make(chan *V2, cfg.ExpiredEntrySize)
	onEvicted := func(item *ristretto.Item) {
		v, ok := item.Value.(V1)
		if !ok {
			return
		}
		key := v.GetHash()
		actual, loaded := entries.LoadAndDelete(key)
		if !loaded {
			return
		}
		entry, ok := actual.(V1)
		if !ok {
			return
		}
		saveToFlush := entry.ConvertToData()
		for _, v2 := range saveToFlush {
			expiredEntries <- v2
		}
	}
	rConfig := ristretto.Config{
		MaxCost:            int64(cfg.EntrySize),
		NumCounters:        int64(cfg.EntrySize) * 10,
		OnEvict:            onEvicted,
		Metrics:            cfg.MetricEnabled,
		BufferItems:        64,
		IgnoreInternalCost: true, //TODO: what is this??
	}
	expirableCache, err := ristretto.NewCache(&rConfig)
	if err != nil {
		return nil, err
	}
	return &Cache[V1, V2]{
		cfg:            cfg,
		expirableCache: expirableCache,
		expiredEntries: expiredEntries,
		entries:        entries,
	}, nil
}

// func (c *Cache[V1, V2]) LoadOrStore(key string, newEntry V1) (V1, bool, error) {
// 	entryKey := key
// 	_entry, loaded := c.entries.LoadOrStore(entryKey, newEntry)
// 	if !loaded {
// 		c.expirableCache.SetWithTTL(entryKey, newEntry, c.cfg.RistrettoConfig.MaxCost, c.cfg.EntryTTL)
// 		_entry = newEntry
// 	}
// 	entry, ok := _entry.(V1)
// 	if !ok {
// 		return entry, false, fmt.Errorf("not a valid convertable type?")
// 	}
// 	return entry, loaded, nil
// }

func (c *Cache[V1, V2]) LoadOrStore(key string, newEntry V1) (V1, error) {
	entryKey := key
	_entry, loaded := c.entries.LoadOrStore(entryKey, newEntry)
	if !loaded {
		c.expirableCache.SetWithTTL(entryKey, newEntry, 1, c.cfg.EntryTTL)
		_entry = newEntry
	}
	entry, ok := _entry.(V1)
	if !ok {
		return entry, fmt.Errorf("not a valid convertable type?")
	}
	return entry, nil
}

func (c *Cache[V1, V2]) GetBatchExpiredEntries(parentCtx context.Context, timeout time.Duration, batchSize int) ([]*V2, error) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	var batch []*V2
	for size := 0; size < batchSize; size++ {
		select {
		case <-ctx.Done():
			return batch, fmt.Errorf("timeout waiting for expired entries ")
		case item := <-c.expiredEntries:
			batch = append(batch, item)
		}
	}
	return batch, nil
}

// func (c *Cache[V1, V2]) onEvicted(item *ristretto.Item) {
// 	v, ok := item.Value.(V1)
// 	if !ok {
// 		return
// 	}
// 	key := v.GetHash()
// 	actual, loaded := c.entries.LoadAndDelete(key)
// 	if !loaded {
// 		return
// 	}
// 	entry, ok := actual.(V1)
// 	if !ok {
// 		return
// 	}
// 	saveToFlush := entry.ConvertToData()
// 	for _, v2 := range saveToFlush {
// 		c.saveToExpiredEntries(v2)
// 	}
// }

// func (c *Cache[V1, V2]) saveToExpiredEntries(entry *V2) {
// 	//TODO: make timeout configurable
// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
// 	defer cancel()
// 	select {
// 	case <-ctx.Done():
// 		return
// 	case c.expiredEntries <- entry:
// 		return
// 	}
// }
