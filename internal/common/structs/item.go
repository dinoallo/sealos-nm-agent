package structs

import (
	"time"

	"github.com/cilium/cilium/pkg/identity"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
)

type TrafficRecordMetaData struct {
	Dir consts.TrafficDirection `bson:"dir"`
	IP  string                  `bson:"ip"`
	Tag string                  `bson:"tag"`
}
type TrafficRecord struct {
	TrafficRecordMeta TrafficRecordMetaData `bson:"traffic_record_meta"`
	DataBytes         uint32                `bson:"data_bytes"`
	ID                string                `bson:"tr_id"`
	Timestamp         time.Time             `bson:"timestamp"`
}

type TrafficReportMetaData struct {
	SrcIP   string `bson:"src_ip"`
	SrcPort uint32 `bson:"src_port"`
	DstIP   string `bson:"dst_ip"`
	DstPort uint32 `bson:"dst_port"`
}

type TrafficReport struct {
	TrafficReportMeta TrafficReportMetaData    `bson:"traffic_report_meta"`
	Dir               consts.TrafficDirection  `bson:"direction"`
	Protocol          uint32                   `bson:"protocol"`
	Family            uint32                   `bson:"family"`
	DataBytes         uint32                   `bson:"data_bytes"`
	Identity          identity.NumericIdentity `bson:"identity"`
	Timestamp         time.Time                `bson:"timestamp"`
}

type CiliumEndpoint struct {
	EndpointID  int64     `bson:"endpoint_id"`
	CreatedTime time.Time `bson:"created_time"`
	DeletedTime time.Time `bson:"deleted_time"`
	ID          string    `bson:"cep_id"`
	Node        string    `bson:"node"`
}

func (cep *CiliumEndpoint) IsIrrelevant(currentNode string) bool {
	return !cep.DeletedTime.IsZero() || cep.Node != currentNode
}
