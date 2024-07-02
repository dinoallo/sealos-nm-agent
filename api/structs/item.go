package structs

import (
	"time"
)

const (
	HostTrafficTimeField = "timestamp"
	HostTrafficMetaField = "host_traffic_meta"
	PodTrafficTimeField  = "timestamp"
	PodTrafficMetaField  = "traffic_meta"
)

// TODO: total tcp, total udp, etc

type RawTrafficAddrInfo struct {
	IP   string
	Port uint32
}

type RawTrafficMetaData struct {
	Src      RawTrafficAddrInfo
	Dst      RawTrafficAddrInfo
	Protocol uint32
	Family   uint32
}

type RawTraffic struct {
	Meta      RawTrafficMetaData
	ID        int64
	DataBytes uint32
}

type HostTrafficMeta struct {
	IP   string `bson:"ip"`
	Port uint32 `bson:"port"`
}

type HostTraffic struct {
	HostTrafficMeta   `bson:"host_traffic_meta"`
	HostTrafficMetric `bson:"host_traffic_metric"`
	Timestamp         time.Time `bson:"timestamp"`
}

type HostTrafficMetric struct {
	SentBytes uint64 `bson:"sent_bytes"`
	RecvBytes uint64 `bson:"recv_bytes"`
}

type PodMeta struct {
	Name      string
	Namespace string
	Type      int
	TypeName  string
}

type PodMetric struct {
	SentBytes uint64
	RecvBytes uint64
}

type PodTrafficMeta struct {
	PodName      string `bson:"pod_name"`
	PodNamespace string `bson:"pod_namespace"`
	PodAddress   string `bson:"pod_address"`
	TrafficTag   string `bson:"traffic_tag"`
	PodType      int    `bson:"pod_type"`
	PodTypeName  string `bson:"pod_type_name"`
}

type PodTraffic struct {
	PodTrafficMeta `bson:"traffic_meta"`
	SentBytes      uint64    `bson:"sent_bytes"`
	RecvBytes      uint64    `bson:"recv_bytes"`
	Timestamp      time.Time `bson:"timestamp"`
}
