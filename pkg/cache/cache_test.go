package cache

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"

	zaplog "github.com/dinoallo/sealos-networkmanager-agent/pkg/log/zap"
	"github.com/stretchr/testify/assert"
)

type V1 struct {
	Key   string
	Value map[string]string
}

func (v *V1) GetHash() string {
	return v.Key
}

func (v *V1) ConvertToData() []*V2 {
	var v2s []*V2
	for k, v := range v.Value {
		v2Value := fmt.Sprintf("%s: %s", k, v)
		v2s = append(v2s, &V2{Value: v2Value})
	}
	return v2s
}

type V2 struct {
	Value string
}

var (
	cache *Cache[*V1, V2]
)

func TestLoadingOrStoring(t *testing.T) {
	newEntry := generateV1()
	key := newEntry.GetHash()
	t.Run("store an v1 entry", func(t *testing.T) {
		_, err := cache.LoadOrStore(key, newEntry)
		assert.NoError(t, err)
	})
	t.Run("load an v1 entry", func(t *testing.T) {
		entry, err := cache.LoadOrStore(key, newEntry)
		if assert.NoError(t, err) && assert.NotNil(t, entry) {
			assert.Equal(t, newEntry, entry)
		}
	})
}

func TestGettingBatchExpiredEntries(t *testing.T) {
	ctx := context.Background()
	timeout := time.Second * 10
	batchSize := 5
	t.Run("load some entries", func(t *testing.T) {
		for i := 0; i < batchSize; i++ {
			entry := generateV1()
			key := entry.GetHash()
			_, err := cache.LoadOrStore(key, entry)
			assert.NoError(t, err)
		}
	})
	t.Run("get some expired entries", func(t *testing.T) {
		entries, err := cache.GetBatchExpiredEntries(ctx, timeout, batchSize)
		if assert.NoError(t, err) && assert.Equal(t, batchSize, len(entries)) {
			for i, entry := range entries {
				t.Logf("entry %v: %v", i, entry)
			}
		}
	})
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := cryptorand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func generateV1() *V1 {
	mapLen := rand.Intn(4) + 1
	v1Values := make(map[string]string, mapLen)
	for i := 0; i < mapLen; i++ {
		k := generateRandomString(16)
		v := generateRandomString(5)
		v1Values[k] = v
	}
	key := generateRandomString(16)
	return &V1{
		Key:   key,
		Value: v1Values,
	}
}

func TestMain(m *testing.M) {
	cacheConfig := NewCacheConfig()
	cacheConfig.EntryTTL = 2 * time.Second
	logger, err := zaplog.NewZap(true)
	if err != nil {
		log.Fatalf("cannot init a logger for testing purpose: %v", err)
	}
	_cache, err := NewCache[*V1, V2](cacheConfig)
	if err != nil {
		logger.Fatal(err)
	}
	cache = _cache
	os.Exit(m.Run())
}
