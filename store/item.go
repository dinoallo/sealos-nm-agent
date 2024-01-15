package store

import (
	"time"

	"github.com/cilium/cilium/pkg/identity"
)

type Property struct {
	SentBytes uint64 `bson:"sent_bytes"`
	RecvBytes uint64 `bson:"recv_bytes"`
}

type TrafficAccount struct {
	IP         string              `bson:"ip"`
	Properties map[string]Property `bson:"properties"`
}

const (
	TRAFFIC_REPORT_TIME_FIELD = "timestamp"
	TRAFFIC_REPORT_META_FIELD = "traffic_report_meta"
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
	Node        string `bson:"node"`
	CreatedTime int64  `bson:"created_time"`
}
