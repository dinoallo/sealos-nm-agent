package cache

import (
	"container/heap"
	"context"
	"fmt"
	"sync"
	"time"
)

type Convertable[V2 any] interface {
	GetHash() string
	ConvertToData() []*V2
}

type CacheConfig struct {
	EntryTTL         time.Duration
	ExpiredEntrySize int
	EntrySize        int
}

func NewCacheConfig() CacheConfig {
	return CacheConfig{
		EntryTTL:         300 * time.Second,
		ExpiredEntrySize: 1e4,
		EntrySize:        1e6,
	}
}

type cacheEntry[V any] struct {
	key       string
	value     V
	expiresAt time.Time
}

type expirationHeap[V any] []*cacheEntry[V]

func (h expirationHeap[V]) Len() int           { return len(h) }
func (h expirationHeap[V]) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h expirationHeap[V]) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *expirationHeap[V]) Push(value any) {
	entry, ok := value.(*cacheEntry[V])
	if !ok {
		panic("cache: invalid expiration heap entry")
	}
	*h = append(*h, entry)
}

func (h *expirationHeap[V]) Pop() any {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	*h = old[:last]
	return entry
}

type Cache[V1 Convertable[V2], V2 any] struct {
	cfg CacheConfig

	entries        sync.Map
	entryMu        sync.Mutex
	entryCond      *sync.Cond
	entryCount     int
	closed         bool
	expirationMu   sync.Mutex
	expirations    expirationHeap[V1]
	expiredEntries chan *V2
	wakeExpiry     chan struct{}
	stopExpiry     chan struct{}
	expiryDone     chan struct{}
	closeOnce      sync.Once
}

func NewCache[V1 Convertable[V2], V2 any](cfg CacheConfig) (*Cache[V1, V2], error) {
	if cfg.EntryTTL <= 0 {
		return nil, fmt.Errorf("entry TTL must be positive")
	}
	if cfg.EntrySize <= 0 {
		return nil, fmt.Errorf("entry size must be positive")
	}
	if cfg.ExpiredEntrySize < 0 {
		return nil, fmt.Errorf("expired entry size cannot be negative")
	}

	c := &Cache[V1, V2]{
		cfg:            cfg,
		expiredEntries: make(chan *V2, cfg.ExpiredEntrySize),
		wakeExpiry:     make(chan struct{}, 1),
		stopExpiry:     make(chan struct{}),
		expiryDone:     make(chan struct{}),
	}
	c.entryCond = sync.NewCond(&c.entryMu)
	heap.Init(&c.expirations)
	go c.runExpiry()
	return c, nil
}

func (c *Cache[V1, V2]) LoadOrStore(key string, newValue V1) (V1, error) {
	if actual, loaded := c.entries.Load(key); loaded {
		entry, ok := actual.(*cacheEntry[V1])
		if !ok {
			var zero V1
			return zero, fmt.Errorf("invalid cache entry type")
		}
		return entry.value, nil
	}

	// Allow one overflow entry so the expiry worker can evict the oldest entry
	// and release capacity. Further writers wait while the output queue is
	// backpressured instead of allowing the heap to grow without bound.
	c.entryMu.Lock()
	for c.entryCount > c.cfg.EntrySize && !c.closed {
		c.entryCond.Wait()
	}
	if c.closed {
		c.entryMu.Unlock()
		var zero V1
		return zero, ErrCacheClosed
	}
	c.entryCount++

	newEntry := &cacheEntry[V1]{
		key:       key,
		value:     newValue,
		expiresAt: time.Now().Add(c.cfg.EntryTTL),
	}
	actual, loaded := c.entries.LoadOrStore(key, newEntry)
	if loaded {
		c.entryCount--
		c.entryCond.Broadcast()
		c.entryMu.Unlock()
		entry, ok := actual.(*cacheEntry[V1])
		if !ok {
			var zero V1
			return zero, fmt.Errorf("invalid cache entry type")
		}
		return entry.value, nil
	}

	c.scheduleExpiry(newEntry)
	c.entryMu.Unlock()
	return newValue, nil
}

func (c *Cache[V1, V2]) GetBatchExpiredEntries(parentCtx context.Context, timeout time.Duration, batchSize int) ([]*V2, error) {
	if batchSize <= 0 {
		return nil, fmt.Errorf("batch size must be positive")
	}

	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	var batch []*V2
	for len(batch) < batchSize {
		select {
		case <-ctx.Done():
			return batch, ErrTimeoutGettingExpiredEntries
		case item := <-c.expiredEntries:
			batch = append(batch, item)
		}
	}
	return batch, nil
}

func (c *Cache[V1, V2]) Close() {
	c.closeOnce.Do(func() {
		c.entryMu.Lock()
		c.closed = true
		c.entryCond.Broadcast()
		c.entryMu.Unlock()
		close(c.stopExpiry)
		<-c.expiryDone
	})
}

func (c *Cache[V1, V2]) releaseEntry() {
	c.entryMu.Lock()
	c.entryCount--
	c.entryCond.Broadcast()
	c.entryMu.Unlock()
}

func (c *Cache[V1, V2]) scheduleExpiry(entry *cacheEntry[V1]) {
	c.expirationMu.Lock()
	wake := len(c.expirations) == 0 || entry.expiresAt.Before(c.expirations[0].expiresAt)
	heap.Push(&c.expirations, entry)
	wake = wake || len(c.expirations) > c.cfg.EntrySize
	c.expirationMu.Unlock()

	if wake {
		select {
		case c.wakeExpiry <- struct{}{}:
		default:
		}
	}
}

func (c *Cache[V1, V2]) runExpiry() {
	defer close(c.expiryDone)
	for {
		wait, exists := c.nextExpiry()
		if !exists {
			select {
			case <-c.wakeExpiry:
				continue
			case <-c.stopExpiry:
				return
			}
		}

		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-c.wakeExpiry:
				if !timer.Stop() {
					<-timer.C
				}
				continue
			case <-c.stopExpiry:
				if !timer.Stop() {
					<-timer.C
				}
				return
			}
		}

		entry := c.popExpiredOrOverflowEntry(time.Now())
		if entry == nil {
			continue
		}
		if !c.entries.CompareAndDelete(entry.key, entry) {
			c.releaseEntry()
			continue
		}
		c.releaseEntry()
		for _, item := range entry.value.ConvertToData() {
			select {
			case c.expiredEntries <- item:
			case <-c.stopExpiry:
				return
			}
		}
	}
}

func (c *Cache[V1, V2]) nextExpiry() (time.Duration, bool) {
	c.expirationMu.Lock()
	defer c.expirationMu.Unlock()
	if len(c.expirations) == 0 {
		return 0, false
	}
	if len(c.expirations) > c.cfg.EntrySize {
		return 0, true
	}
	return time.Until(c.expirations[0].expiresAt), true
}

func (c *Cache[V1, V2]) popExpiredOrOverflowEntry(now time.Time) *cacheEntry[V1] {
	c.expirationMu.Lock()
	defer c.expirationMu.Unlock()
	if len(c.expirations) == 0 {
		return nil
	}
	if len(c.expirations) <= c.cfg.EntrySize && c.expirations[0].expiresAt.After(now) {
		return nil
	}
	entry, ok := heap.Pop(&c.expirations).(*cacheEntry[V1])
	if !ok {
		panic("cache: invalid expiration heap entry")
	}
	return entry
}
