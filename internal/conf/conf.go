package conf

import (
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	DB_URI_ENV = "DB_URI"

	TRSTORE_DEFAULT_MAX_WORKER_COUNT         = (1 << 6)
	TRSTORE_DEFAULT_MAX_RECVER_COUNT         = (1 << 3)
	TRSTORE_DEFAULT_MONITOR_SYNC_PERIOD      = 60
	TRSTORE_DEFAULT_MAX_MONITOR_ENTRIES_SIZE = (1 << 20)
	TRSTORE_DEFAULT_MAX_RECORD_TO_FLUSH      = (1 << 15)
	TRSTORE_DEFAULT_MAX_RECORD_QUEUE_LEN     = (1 << 20)
	TRSTORE_DEFAULT_MAX_REPORT_QUEUE_LEN     = (1 << 20)
	TRSTORE_DEFAULT_MAX_RECORD_WAITING_TIME  = 60
	TRSTORE_DEFAULT_TRAFFIC_RECORD_COLL      = "traffic_records"
	TRSTORE_DEFAULT_FLUSHING_TIMEOUT         = 60

	CEPSTORE_DEFAULT_MAX_WORKER_COUNT          = 5
	CEPSTORE_DEFAULT_PTI                       = "stale"
	CEPSTORE_DEFAULT_ENDPOINT_SYNC_PERIOD      = 60
	CEPSTORE_DEFAULT_MAX_ENDPOINT_ENTRIES_SIZE = (1 << 25)
	CEPSTORE_DEFAULT_CILIUM_ENDPOINT_COLL      = "cilium_endpoints"

	PS_DEFAULT_DB_NAME            = "sealos-networkmanager"
	PS_DEFAULT_CONNECTION_TIMEOUT = 10
	PS_DEFAULT_EXPIRE_AFTER       = 1800
	PS_DEFAULT_MAX_POOL_SIZE      = 100

	BYTECOUNT_FACTORY_DEFAULT_PERF_BUFFER_SIZE      = (64 << 10) // 64KB
	BYTECOUNT_FACTORY_DEFAULT_MAX_READER_COUNT      = (1 << 0)
	BYTECOUNT_FACTORY_DEFAULT_MAX_PROCESSOR_COUNT   = (1 << 3)
	BYTECOUNT_FACTORY_DEFAULT_MAX_TRAFFIC_QUEUE_LEN = (1 << 20)

	TRAFFIC_SERVICE_DEFAULT_MAX_CONNECTION_IDLE = 15
)

type TrafficRecordStoreConfig struct {
	// the max number of workers to concurrently flush traffic records to the database
	MaxWorkerCount int `yaml:"max_worker_count"`
	// the max number of recvers to receive traffic reports
	MaxRecverCount int `yaml:"max_recver_count"`
	// the time period(seconds) to evict traffic monitors in the temp storage and flush data to the database
	MonitorSyncPeriod int `yaml:"monitor_sync_period"`
	// the max size of temp storage to store traffic monitors
	MaxMonitorEntriesSize int `yaml:"max_monitor_entries_size"`
	// the max number of traffic records to flush at the same time per manager
	MaxRecordToFlush int `yaml:"max_record_to_flush"`
	// the max size of channel to temporarily store traffic reports before recver processing
	MaxReportQueueLen int `yaml:"max_report_queue_len"`
	// the max size of channel to temporarily store traffic records before manager processing
	MaxRecordQueueLen int `yaml:"max_record_queue_len"`
	// the max time (seconds) for manager to wait for records before a data flush
	MaxRecordWaitingTime int `yaml:"max_record_waiting_time"`
	// the collection name for storing TrafficRecord to database
	TrafficRecordColl string `yaml:"traffic_record_coll"`
}

type CiliumEndpointStoreConfig struct {
	// the max number of workers to concurrently flush cilium endpoints to the database
	MaxWorkerCount int `yaml:"max_worker_count"`
	// the name for the partial ttl index on cilium endpoints
	PartialTTLIndex string `yaml:"partial_ttl_index"`
	// the time period(seconds) to evict cilium endopints in the temp storage and flush data to the database
	EndpointSyncPeriod int `yaml:"endpoint_sync_period"`
	// the max size of temp storage to store cilium endpoints
	MaxEndpointEntriesSize int `yaml:"max_endpoint_entries_size"`
	// the collection name for storing CiliumEndpoint to database
	CiliumEndpointColl string `yaml:"cilium_endpoint_coll"`
}

type PersistentStorageConfig struct {
	// the database name
	DBName string `yaml:"db_name"`
	// the max waiting time to get a response from database (in seconds)
	ConnectionTimeout int `yaml:"connection_timeout"`
	// the max number of concurrent database connections
	MaxPoolSize int `yaml:"max_pool_size"`
	// the ttl for an entry in database (in seconds)
	ExpireAfter int `yaml:"expire_after"`
}

type BytecountFactoryConfig struct {
	PerfBufferSize     int `yaml:"perf_buffer_size"`
	MaxReaderCount     int `yaml:"max_reader_count"`
	MaxProcessorCount  int `yaml:"max_processor_count"`
	MaxTrafficQueueLen int `yaml:"max_traffic_queue_len"`
}

type TrafficServiceConfig struct {
	MaxConnectionIdle int `yaml:"max_connection_idle"`
}

type MainConfig struct {
	*TrafficRecordStoreConfig  `yaml:"traffic_record_store"`
	*PersistentStorageConfig   `yaml:"persistent_storage"`
	*CiliumEndpointStoreConfig `yaml:"cilium_endpoint_store"`
	*BytecountFactoryConfig    `yaml:"bytecount_factory"`
	*TrafficServiceConfig      `yaml:"traffic_service"`
}

func InitConfig(logger *zap.SugaredLogger, devMode bool) (*MainConfig, error) {
	mainConf := MainConfig{
		TrafficRecordStoreConfig:  NewTrafficRecordStoreConfig(),
		CiliumEndpointStoreConfig: NewCiliumEndpointStoreConfig(),
		PersistentStorageConfig:   NewPersistentStorageConfig(),
		BytecountFactoryConfig:    NewBytecountFactoryConfig(),
		TrafficServiceConfig:      NewTrafficServiceConfig(),
	}
	if configFile, err := os.Open("/etc/sealos-nm-agent/config/config.yml"); err != nil {
		return nil, err
	} else {
		defer configFile.Close()
		decoder := yaml.NewDecoder(configFile)
		if err := decoder.Decode(&mainConf); err != nil {
			return nil, err
		}
	}
	if devMode {
		logger.Debugf("print persistent storage config: ")
		if err := printYamlConfig(logger, *(mainConf.PersistentStorageConfig)); err != nil {
			return nil, err
		}
		logger.Debugf("print traffic record store config: ")
		if err := printYamlConfig(logger, *(mainConf.TrafficRecordStoreConfig)); err != nil {
			return nil, err
		}
		logger.Debugf("print cilium endpoint store config: ")
		if err := printYamlConfig(logger, *(mainConf.CiliumEndpointStoreConfig)); err != nil {
			return nil, err
		}
		logger.Debugf("print bytecount factory config: ")
		if err := printYamlConfig(logger, *(mainConf.BytecountFactoryConfig)); err != nil {
			return nil, err
		}
		logger.Debugf("print traffic service config: ")
		if err := printYamlConfig(logger, *(mainConf.TrafficServiceConfig)); err != nil {
			return nil, err
		}
	}

	return &mainConf, nil
}

// new functions here
func NewTrafficRecordStoreConfig() *TrafficRecordStoreConfig {
	return &TrafficRecordStoreConfig{
		MaxWorkerCount:        TRSTORE_DEFAULT_MAX_WORKER_COUNT,
		MaxRecverCount:        TRSTORE_DEFAULT_MAX_RECVER_COUNT,
		MonitorSyncPeriod:     TRSTORE_DEFAULT_MONITOR_SYNC_PERIOD,
		MaxMonitorEntriesSize: TRSTORE_DEFAULT_MAX_MONITOR_ENTRIES_SIZE,
		MaxRecordToFlush:      TRSTORE_DEFAULT_MAX_RECORD_TO_FLUSH,
		MaxReportQueueLen:     TRSTORE_DEFAULT_MAX_REPORT_QUEUE_LEN,
		MaxRecordQueueLen:     TRSTORE_DEFAULT_MAX_RECORD_QUEUE_LEN,
		MaxRecordWaitingTime:  TRSTORE_DEFAULT_MAX_RECORD_WAITING_TIME,
		TrafficRecordColl:     TRSTORE_DEFAULT_TRAFFIC_RECORD_COLL,
	}
}

func NewCiliumEndpointStoreConfig() *CiliumEndpointStoreConfig {
	return &CiliumEndpointStoreConfig{
		MaxWorkerCount:         CEPSTORE_DEFAULT_MAX_WORKER_COUNT,
		PartialTTLIndex:        CEPSTORE_DEFAULT_PTI,
		EndpointSyncPeriod:     CEPSTORE_DEFAULT_ENDPOINT_SYNC_PERIOD,
		MaxEndpointEntriesSize: CEPSTORE_DEFAULT_MAX_ENDPOINT_ENTRIES_SIZE,
		CiliumEndpointColl:     CEPSTORE_DEFAULT_CILIUM_ENDPOINT_COLL,
	}
}

func NewPersistentStorageConfig() *PersistentStorageConfig {
	return &PersistentStorageConfig{
		DBName:            PS_DEFAULT_DB_NAME,
		ConnectionTimeout: PS_DEFAULT_CONNECTION_TIMEOUT,
		MaxPoolSize:       PS_DEFAULT_MAX_POOL_SIZE,
		ExpireAfter:       PS_DEFAULT_EXPIRE_AFTER,
	}
}

func NewBytecountFactoryConfig() *BytecountFactoryConfig {
	return &BytecountFactoryConfig{
		PerfBufferSize:     BYTECOUNT_FACTORY_DEFAULT_PERF_BUFFER_SIZE,
		MaxReaderCount:     BYTECOUNT_FACTORY_DEFAULT_MAX_READER_COUNT,
		MaxProcessorCount:  BYTECOUNT_FACTORY_DEFAULT_MAX_PROCESSOR_COUNT,
		MaxTrafficQueueLen: BYTECOUNT_FACTORY_DEFAULT_MAX_TRAFFIC_QUEUE_LEN,
	}
}

func NewTrafficServiceConfig() *TrafficServiceConfig {
	return &TrafficServiceConfig{
		MaxConnectionIdle: TRAFFIC_SERVICE_DEFAULT_MAX_CONNECTION_IDLE,
	}
}
