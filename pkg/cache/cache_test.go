package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type V1 struct {
	Key   string
	Value map[string]string
}

func (v *V1) GetHash() string {
	return v.Key
}

func (v *V1) ConvertToData() []*V2 {
	v2s := make([]*V2, 0, len(v.Value))
	for key, value := range v.Value {
		v2s = append(v2s, &V2{Value: fmt.Sprintf("%s: %s", key, value)})
	}
	return v2s
}

type V2 struct {
	Value string
}

func TestLoadOrStoreReturnsOneStableEntry(t *testing.T) {
	c := newTestCache(t, time.Minute, 100)
	first := &V1{Key: "key", Value: map[string]string{"first": "value"}}
	second := &V1{Key: "key", Value: map[string]string{"second": "value"}}

	stored, err := c.LoadOrStore(first.Key, first)
	require.NoError(t, err)
	assert.Same(t, first, stored)

	stored, err = c.LoadOrStore(second.Key, second)
	require.NoError(t, err)
	assert.Same(t, first, stored)
}

func TestConcurrentLoadOrStoreReturnsOneStableEntry(t *testing.T) {
	c := newTestCache(t, time.Minute, 100)
	const workers = 32

	results := make(chan *V1, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(value int) {
			defer wg.Done()
			entry := &V1{Key: "key", Value: map[string]string{"value": fmt.Sprint(value)}}
			stored, err := c.LoadOrStore(entry.Key, entry)
			errs <- err
			results <- stored
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	var first *V1
	for result := range results {
		if first == nil {
			first = result
		}
		assert.Same(t, first, result)
	}
}

func TestLargeCapacityIsAllocatedLazily(t *testing.T) {
	c, err := NewCache[*V1, V2](NewCacheConfig())
	require.NoError(t, err)
	t.Cleanup(c.Close)

	c.expirationMu.Lock()
	defer c.expirationMu.Unlock()
	assert.Empty(t, c.expirations)
}

func TestEntryExpiresAndIsConverted(t *testing.T) {
	c := newTestCache(t, 20*time.Millisecond, 100)
	entry := &V1{Key: "key", Value: map[string]string{"metric": "42"}}
	_, err := c.LoadOrStore(entry.Key, entry)
	require.NoError(t, err)

	expired, err := c.GetBatchExpiredEntries(context.Background(), time.Second, 1)
	require.NoError(t, err)
	require.Len(t, expired, 1)
	assert.Equal(t, "metric: 42", expired[0].Value)
}

func TestCapacityExpiresOldestEntry(t *testing.T) {
	c := newTestCache(t, time.Hour, 1)
	first := &V1{Key: "first", Value: map[string]string{"key": "first"}}
	second := &V1{Key: "second", Value: map[string]string{"key": "second"}}

	_, err := c.LoadOrStore(first.Key, first)
	require.NoError(t, err)
	_, err = c.LoadOrStore(second.Key, second)
	require.NoError(t, err)

	expired, err := c.GetBatchExpiredEntries(context.Background(), time.Second, 1)
	require.NoError(t, err)
	require.Len(t, expired, 1)
	assert.Equal(t, "key: first", expired[0].Value)

	stored, err := c.LoadOrStore(second.Key, &V1{Key: "second"})
	require.NoError(t, err)
	assert.Same(t, second, stored)
}

func TestNewCacheRejectsInvalidConfig(t *testing.T) {
	tests := []CacheConfig{
		{EntryTTL: 0, EntrySize: 1},
		{EntryTTL: time.Second, EntrySize: 0},
		{EntryTTL: time.Second, EntrySize: 1, ExpiredEntrySize: -1},
	}
	for _, cfg := range tests {
		_, err := NewCache[*V1, V2](cfg)
		assert.Error(t, err)
	}
}

func TestGetBatchExpiredEntriesRejectsInvalidBatchSize(t *testing.T) {
	c := newTestCache(t, time.Minute, 100)

	for _, batchSize := range []int{0, -1} {
		expired, err := c.GetBatchExpiredEntries(context.Background(), time.Second, batchSize)
		require.Error(t, err)
		assert.Nil(t, expired)
	}
}

func newTestCache(t *testing.T, ttl time.Duration, size int) *Cache[*V1, V2] {
	t.Helper()
	c, err := NewCache[*V1, V2](CacheConfig{
		EntryTTL:         ttl,
		ExpiredEntrySize: 100,
		EntrySize:        size,
	})
	require.NoError(t, err)
	t.Cleanup(c.Close)
	return c
}
