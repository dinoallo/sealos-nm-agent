package store

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/identity"
)

type TrafficMonitorMetrics struct {
	SentBytes atomic.Uint32
	RecvBytes atomic.Uint32
}

type TrafficMonitor struct {
	IP           string
	PortMetrics  map[uint32]*TrafficMonitorMetrics // ordered by port number
	WorldMetrics *TrafficMonitorMetrics
	wmMu         sync.RWMutex
	pmMu         sync.RWMutex
}

type TrafficRecordMetaData struct {
	Dir TrafficDirection `bson:"dir"`
	IP  string           `bson:"ip"`
	Tag string           `bson:"tag"`
}
type TrafficRecord struct {
	TrafficRecordMeta TrafficRecordMetaData `bson:"traffic_record_meta"`
	DataBytes         uint32                `bson:"data_bytes"`
	ID                string                `bson:"tr_id"`
	Timestamp         time.Time             `bson:"timestamp"`
}

const (
	TRAFFIC_REPORT_TIME_FIELD = "timestamp"
	TRAFFIC_REPORT_META_FIELD = "traffic_report_meta"

	TRAFFIC_RECORD_TIME_FIELD = "timestamp"
	TRAFFIC_RECORD_META_FIELD = "traffic_report_meta"
)

type TrafficReportMetaData struct {
	SrcIP   string `bson:"src_ip"`
	SrcPort uint32 `bson:"src_port"`
	DstIP   string `bson:"dst_ip"`
	DstPort uint32 `bson:"dst_port"`
}

type TrafficReport struct {
	TrafficReportMeta TrafficReportMetaData    `bson:"traffic_report_meta"`
	Dir               TrafficDirection         `bson:"direction"`
	Protocol          uint32                   `bson:"protocol"`
	Family            uint32                   `bson:"family"`
	DataBytes         uint32                   `bson:"data_bytes"`
	Identity          identity.NumericIdentity `bson:"identity"`
	Timestamp         time.Time                `bson:"timestamp"`
}

type CiliumEndpoint struct {
	EndpointID  int64  `bson:"endpoint_id"`
	CreatedTime int64  `bson:"created_time"`
	DeletedTime int64  `bson:"deleted_time"`
	ID          string `bson:"cep_id"`
	Node        string `bson:"node"`
}
