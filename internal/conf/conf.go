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

type HostTrafficStoreConfig struct { // envPrefix: HTS_
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

func NewHostTrafficStoreConfig() HostTrafficStoreConfig {
	return HostTrafficStoreConfig{
		Enabled:               true,
		DefaultColl:           "host_traffic",
		MaxWorkerCount:        5,
		FlushTimeout:          time.Second * 5,
		GetBatchTimeout:       time.Second * 5,
		BatchSize:             100,
		CacheEntryTTL:         time.Second * 60,
		CacheExpiredEntrySize: 1e4,
		CacheEntrySize:        1e6,
	}
}

type NetworkDeviceWatcherConfig struct { // envPrefix: NDW_
	WatchPeriod time.Duration `env:"WATCH_PERIOD"`
}

func NewNetworkDeviceWatcherConfig() NetworkDeviceWatcherConfig {
	return NetworkDeviceWatcherConfig{
		WatchPeriod: 10 * time.Second,
	}
}

type CiliumCCMWatcherConfig struct { // envPrefix: CCMW_
	WatchPeriod time.Duration `env:"WATCH_PERIOD"`
}

func NewCiliumCCMWatcherConfig() CiliumCCMWatcherConfig {
	return CiliumCCMWatcherConfig{
		WatchPeriod: time.Second * 10,
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
	// if this option is set to true, the agent will watch the cilium endpoints' custom call maps
	// instead of their lxc devices, which also means the agent will receive traffic events by
	// cilium tail-calling our programs via custom call maps
	// this feature requires using cilium as cni and enable custom call hook
	WatchCiliumEndpoint        bool `env:"WATCH_CILIUM_ENDPOINT"`
	WatchHost                  bool `env:"WATCH_HOST"`
	ClassifierConfig           `envPrefix:"CLS_"`
	PodTrafficStoreConfig      `envPrefix:"PTS_"`
	HostTrafficStoreConfig     `envPrefix:"HTS_"`
	DBConfig                   `envPrefix:"DB_"`
	BPFTrafficFactoryConfig    `envPrefix:"TF_"`
	NetworkDeviceWatcherConfig `envPrefix:"NDW_"`
	CiliumCCMWatcherConfig     `envPrefix:"CCMW_"`
	MockConfig                 `envPrefix:"MOCK_"`
}

func NewGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		WatchCiliumEndpoint:        true,
		WatchHost:                  true,
		ClassifierConfig:           NewClassifierConfig(),
		PodTrafficStoreConfig:      NewPodTrafficStoreConfig(),
		HostTrafficStoreConfig:     NewHostTrafficStoreConfig(),
		DBConfig:                   NewDBConfig(),
		BPFTrafficFactoryConfig:    NewBPFTrafficFactoryConfig(),
		NetworkDeviceWatcherConfig: NewNetworkDeviceWatcherConfig(),
		CiliumCCMWatcherConfig:     NewCiliumCCMWatcherConfig(),
		MockConfig:                 NewMockConfig(),
	}
}

func InitGlobalConfig() (*GlobalConfig, error) {
	cfg := NewGlobalConfig()
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
