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
	// if `DumpMode` is set to true, the handler will dump packets before they
	// get sent to the store, this is useful when testing and debugging.
	// currently only host traffic dumping is supported
	HostDumpMode bool `env:"HOST_DUMP_MODE"`
	PodDumpMode  bool `env:"POD_DUMP_MODE"`
}

func NewBPFTrafficFactoryConfig() BPFTrafficFactoryConfig {
	return BPFTrafficFactoryConfig{
		ReaderMaxWorker:  5,
		HandlerMaxWorker: 5,
		PodDumpMode:      false,
		HostDumpMode:     false,
	}
}

type ClassifierConfig struct { // envPrefix: CLS_
	Enabled         bool     `env:"ENABLED"`
	HostCIDRList    []string `env:"HOST_CIDR_LIST"`
	NodeCIDRList    []string `env:"NODE_CIDR_LIST"`
	SkippedCIDRList []string `env:"SKIPPED_CIDR_LIST"`
	PodCIDRList     []string `env:"POD_CIDR_LIST"`
}

func NewClassifierConfig() ClassifierConfig {
	return ClassifierConfig{
		Enabled:         true,
		HostCIDRList:    make([]string, 0),
		NodeCIDRList:    make([]string, 0),
		SkippedCIDRList: make([]string, 0),
		PodCIDRList:     make([]string, 0),
	}
}

type TrafficStoreConfig struct { // envPrefix: TS_
	Enabled               bool          `env:"ENABLED"`
	PodTrafficColl        string        `env:"POD_TRAFFIC_COLL"`
	HostTrafficColl       string        `env:"HOST_TRAFFIC_COLL"`
	MaxWorkerCount        int           `env:"MAX_WORKER_COUNT"`
	FlushTimeout          time.Duration `env:"FLUSH_TIMEOUT"`
	GetBatchTimeout       time.Duration `env:"GET_BATCH_TIMEOUT"`
	BatchSize             int           `env:"BATCH_SIZE"`
	CacheEntryTTL         time.Duration `env:"CACHE_ENTRY_TTL"`
	CacheExpiredEntrySize int           `env:"CACHE_EXPIRED_ENTRY_SIZE"`
	CacheEntrySize        int           `env:"CACHE_ENTRY_SIZE"`
}

func NewTrafficStoreConfig() TrafficStoreConfig {
	return TrafficStoreConfig{
		Enabled:               true,
		PodTrafficColl:        "traffic",
		HostTrafficColl:       "host_traffic",
		MaxWorkerCount:        5,
		FlushTimeout:          time.Second * 5,
		GetBatchTimeout:       time.Second * 5,
		BatchSize:             100,
		CacheEntryTTL:         time.Second * 60,
		CacheExpiredEntrySize: 1e4,
		CacheEntrySize:        1e6,
	}
}

type EpWatcherConfig struct {
	MaxWorker int `env:"MAX_WORKER"`
}

func NewEpWatcherConfig() EpWatcherConfig {
	return EpWatcherConfig{
		MaxWorker: 5,
	}
}

type CiliumNodeWatcherConfig struct {
	Enabled   bool `env:"ENABLED"`
	MaxWorker int  `env:"MAX_WORKER"`
}

func NewCiliumNodeWatcherConfig() CiliumNodeWatcherConfig {
	return CiliumNodeWatcherConfig{
		Enabled:   true,
		MaxWorker: 5,
	}
}

type IngressWatcherConfig struct {
	MaxWorker int `env:"MAX_WORKER"`
}

func NewIngressWatcherConfig() IngressWatcherConfig {
	return IngressWatcherConfig{
		MaxWorker: 5,
	}
}

type PodWatcherConfig struct {
	MaxWorker int `env:"MAX_WORKER"`
}

func NewPodWatcherConfig() PodWatcherConfig {
	return PodWatcherConfig{
		MaxWorker: 5,
	}
}

type HostDevWatcherConfig struct {
	HostDevs []string `env:"HOST_DEVS"`
}

func NewHostDevWatcherConfig() HostDevWatcherConfig {
	return HostDevWatcherConfig{
		HostDevs: make([]string, 0),
	}
}

type NetnsWatcherConfig struct {
	NsPattern string `env:"NS_PATTERN"`
	// Max worker counts to do concurrent job like watching inotify events about netns
	MaxWorkerCount int `env:"MAX_WORKER_COUNT"`
}

func NewNetnsWatcherConfig() NetnsWatcherConfig {
	return NetnsWatcherConfig{
		NsPattern:      "^cni",
		MaxWorkerCount: 5,
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

type DebugServiceConfig struct {
	Enabled bool   `env:"ENABLED"`
	Addr    string `env:"ADDR"`
	Pprof   bool   `env:"PPROF"`
}

func NewDebugServiceConfig() DebugServiceConfig {
	return DebugServiceConfig{
		Enabled: false,
		Addr:    "0.0.0.0:6060",
		Pprof:   true,
	}
}

type GlobalConfig struct {
	// the ip of the host that the agent is currently running on
	Host string `env:"AGENT_HOST"`
	// set `EnableHostTraffic` to true to enable watching on host devices. the current
	// implementation still allocates memory for packets from/to host no matter what
	EnableHostTraffic bool `env:"ENABLE_HOST_TRAFFIC"`
	// set `EnablePodTraffic` to true to enable watching on pods. the current
	// implementation still allocates memory for packets from/to pod no matter what
	EnablePodTraffic        bool `env:"ENABLE_POD_TRAFFIC"`
	ClassifierConfig        `envPrefix:"CLS_"`
	TrafficStoreConfig      `envPrefix:"TS_"`
	DBConfig                `envPrefix:"DB_"`
	BPFTrafficFactoryConfig `envPrefix:"TF_"`
	HostDevWatcherConfig    `envPrefix:"HDW_"`
	NetnsWatcherConfig      `envPrefix:"NW_"`
	EpWatcherConfig         `envPrefix:"EPW_"`
	CiliumNodeWatcherConfig `envPrefix:"CNW_"`
	PodWatcherConfig        `envPrefix:"PODW_"`
	IngressWatcherConfig    `envPrefix:"INGW_"`
	DebugServiceConfig      `envPrefix:"DEBUG_"`
	MockConfig              `envPrefix:"MOCK_"`
}

func NewGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		Host:                    "127.0.0.1",
		EnableHostTraffic:       false,
		EnablePodTraffic:        true,
		ClassifierConfig:        NewClassifierConfig(),
		TrafficStoreConfig:      NewTrafficStoreConfig(),
		DBConfig:                NewDBConfig(),
		BPFTrafficFactoryConfig: NewBPFTrafficFactoryConfig(),
		HostDevWatcherConfig:    NewHostDevWatcherConfig(),
		NetnsWatcherConfig:      NewNetnsWatcherConfig(),
		EpWatcherConfig:         NewEpWatcherConfig(),
		CiliumNodeWatcherConfig: NewCiliumNodeWatcherConfig(),
		PodWatcherConfig:        NewPodWatcherConfig(),
		IngressWatcherConfig:    NewIngressWatcherConfig(),
		DebugServiceConfig:      NewDebugServiceConfig(),
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
