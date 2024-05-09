package conf

import (
	"reflect"
	"time"

	raw_traffic "github.com/dinoallo/sealos-networkmanager-agent/internal/traffic"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

var (
	k      = koanf.New(".")
	parser = yaml.Parser()
)

type GlobalConfig struct {
	RawTrafficStoreConfig `koanf:"raw_traffic_store"`
}

type RawTrafficStoreConfig struct {
	DefaultColl                string `koanf:"default_coll"`
	SummaryColl                string `koanf:"summary_coll"`
	MaxWorkerCount             int    `koanf:"max_worker_count"`
	BatchItemCount             int    `koanf:"batch_item_count"`
	GetBatchTimeoutSecond      int    `koanf:"get_batch_timeout_second"`
	FlushTimeoutSecond         int    `koanf:"flush_timeout_second"`
	DefaultCacheEntryTTLSecond int    `koanf:"default_cache_entry_ttl_second"`
	SummaryCacheEntryTTLSecond int    `koanf:"summary_cache_entry_ttl_second"`
}

func ReadGlobalConfig(path string) (GlobalConfig, error) {
	globalConfig := GlobalConfig{}
	if err := k.Load(file.Provider(path), parser); err != nil {
		return globalConfig, err
	}
	if err := k.Unmarshal("", &globalConfig); err != nil {
		return globalConfig, err
	}
	return globalConfig, nil
}

func (c *RawTrafficStoreConfig) ParseRawTrafficStoreConfig() raw_traffic.RawTrafficHandlerConfig {
	cfg := raw_traffic.NewRawTrafficHandlerConfig()
	if isSet(c.DefaultColl) {
		cfg.DefaultColl = c.DefaultColl
	}
	if isSet(c.SummaryColl) {
		cfg.SummaryColl = c.SummaryColl
	}
	if isSet(c.MaxWorkerCount) {
		cfg.MaxWorkerCount = c.MaxWorkerCount
	}
	if isSet(c.BatchItemCount) {
		cfg.GetBatchTimeout = time.Duration(c.GetBatchTimeoutSecond) * time.Second
	}
	if isSet(c.FlushTimeoutSecond) {
		cfg.FlushTimeout = time.Duration(c.FlushTimeoutSecond) * time.Second
	}
	if isSet(c.DefaultCacheEntryTTLSecond) {
		cfg.DefaultCacheConfig.EntryTTL = time.Duration(c.DefaultCacheEntryTTLSecond) * time.Second
	}
	if isSet(c.SummaryCacheEntryTTLSecond) {
		cfg.SummaryCacheConfig.EntryTTL = time.Duration(c.SummaryCacheEntryTTLSecond) * time.Second
	}
	return cfg
}

func isSet(_v any) bool {
	v := reflect.ValueOf(_v)
	switch v.Kind() {
	case reflect.Int:
		return v.Int() != 0
	case reflect.String:
		return v.String() != ""
	default:
		return true
	}
}
