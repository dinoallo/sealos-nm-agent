package conf

import (
	"time"

	"github.com/caarlos0/env/v11"
)

type DBConfig struct { // envPrefix: DB_
	Enabled bool   `env:"ENABLED"`
	Uri     string `env:"URI"`
	Name    string `env:"NAME"`
}

func NewDBConfig() DBConfig {
	return DBConfig{
		Enabled: true,
		Uri:     "",
		Name:    "",
	}
}

type BPFTrafficFactoryConfig struct { // envPrefix: TF_
	ReaderMaxWorker  int `env:"READER_MAX_WORKER"`
	HandlerMaxWorker int `env:"HANDLER_MAX_WORKER"`
}

func NewBPFTrafficFactoryConfig() BPFTrafficFactoryConfig {
	return BPFTrafficFactoryConfig{
		ReaderMaxWorker:  5,
		HandlerMaxWorker: 5,
	}
}

type ClassifierConfig struct { // envPrefix: CLS_
	Enabled         bool     `env:"ENABLED"`
	V4DNSService    string   `env:"V4_DNS_SERVICE"`
	HostCIDRList    []string `env:"HOST_CIDR_LIST"`
	SkippedCIDRList []string `env:"SKIPPED_CIDR_LIST"`
	PodCIDRList     []string `env:"POD_CIDR_LIST"`
}

func NewClassifierConfig() ClassifierConfig {
	return ClassifierConfig{
		Enabled:         true,
		V4DNSService:    "kube-dns.kube-system.svc.cluster.local:53",
		HostCIDRList:    make([]string, 0),
		SkippedCIDRList: make([]string, 0),
		PodCIDRList:     make([]string, 0),
	}
}

type PodTrafficStoreConfig struct { // envPrefix: PTS_
	Enabled               bool          `env:"ENABLED"`
	DefaultColl           string        `env:"DEFAULT_COLL"`
	MaxWorkerCount        int           `env:"MAX_WORKER_COUNT"`
	FlushTimeout          time.Duration `env:"FLUSH_TIMEOUT"`
	GetBatchTimeout       time.Duration `env:"GET_BATCH_TIMEOUT"`
	BatchSize             int           `env:"BATCH_SIZE"`
	CacheEntryTTL         time.Duration `env:"CACHE_ENTRY_TTL"`
	CacheExpiredEntrySize int           `env:"CACHE_EXPIRED_ENTRY_SIZE"`
	CacheEntrySize        int           `env:"CACHE_ENTRY_SIZE"`
}

func NewPodTrafficStoreConfig() PodTrafficStoreConfig {
	return PodTrafficStoreConfig{
		Enabled:               true,
		DefaultColl:           "traffic",
		MaxWorkerCount:        5,
		FlushTimeout:          time.Second * 5,
		GetBatchTimeout:       time.Second * 5,
		BatchSize:             100,
		CacheEntryTTL:         time.Second * 60,
		CacheExpiredEntrySize: 1e4,
		CacheEntrySize:        1e6,
	}
}

type CepWatcherConfig struct {
	Host      string `env:"HOST"`
	MaxWorker int    `env:"MAX_WORKER"`
}

func NewCepWatcherConfig() CepWatcherConfig {
	return CepWatcherConfig{
		Host:      "",
		MaxWorker: 5,
	}
}

type MockConfig struct { // envPrefix: MOCK_
	TrackedPodIP       string `env:"TRACKED_POD_IP"`
	TrackedHostIP      string `env:"TRACKED_HOST_IP"`
	TrackedWorldIP     string `env:"TRACKED_WORLD_IP"`
	TrackedSkippedIP   string `env:"TRACKED_SKIPPED_IP"`
	TrackedExposedPort uint32 `env:"TRACKED_EXPOSED_PORT"`
}

func NewMockConfig() MockConfig {
	return MockConfig{
		TrackedPodIP:       "",
		TrackedHostIP:      "",
		TrackedWorldIP:     "",
		TrackedSkippedIP:   "",
		TrackedExposedPort: 0,
	}
}

type GlobalConfig struct {
	ClassifierConfig        `envPrefix:"CLS_"`
	PodTrafficStoreConfig   `envPrefix:"PTS_"`
	DBConfig                `envPrefix:"DB_"`
	BPFTrafficFactoryConfig `envPrefix:"TF_"`
	CepWatcherConfig        `envPrefix:"CEPW_"`
	MockConfig              `envPrefix:"MOCK_"`
}

func NewGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		ClassifierConfig:        NewClassifierConfig(),
		PodTrafficStoreConfig:   NewPodTrafficStoreConfig(),
		DBConfig:                NewDBConfig(),
		BPFTrafficFactoryConfig: NewBPFTrafficFactoryConfig(),
		CepWatcherConfig:        NewCepWatcherConfig(),
		MockConfig:              NewMockConfig(),
	}
}

func InitGlobalConfig() (*GlobalConfig, error) {
	cfg := NewGlobalConfig()
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
