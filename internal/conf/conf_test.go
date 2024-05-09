package conf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	configPath = "./test.yml"
)

// TODO: test fallback configuration
func TestConfigReadingAndParsing(t *testing.T) {
	var globalConfig GlobalConfig
	var err error
	t.Run("read the config", func(t *testing.T) {
		globalConfig, err = ReadGlobalConfig(configPath)
		assert.NoError(t, err)
	})
	t.Run("raw_traffic_store configured", func(t *testing.T) {
		if assert.NoError(t, err) {
			assert.Equal(t, 50, globalConfig.RawTrafficStoreConfig.DefaultCacheEntryTTLSecond)
		}
	})
	t.Run("parse raw_trafic_store", func(t *testing.T) {
		cfg := globalConfig.ParseRawTrafficStoreConfig()
		if assert.NoError(t, err) {
			assert.Equal(t, 50*time.Second, cfg.DefaultCacheConfig.EntryTTL)
		}
	})
}
