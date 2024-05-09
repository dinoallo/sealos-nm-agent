package structs

import (
	"fmt"
	"time"
)

type RawTrafficEvent struct {
	RawTrafficEventMeta RawTrafficEventMetaData `bson:"meta"`
	ID                  string                  `bson:"id"`
	DataBytes           uint32                  `bson:"data_bytes"`
	Timestamp           time.Time               `bson:"timestamp"`
}

type RawTrafficEventMetaData struct {
	SrcIP    string `bson:"src_ip"`
	SrcPort  uint32 `bson:"src_port"`
	DstIP    string `bson:"dst_ip"`
	DstPort  uint32 `bson:"dst_port"`
	Protocol uint32 `bson:"protocol"`
	Family   uint32 `bson:"family"`
}

// TODO: total tcp, total udp, etc
type RawTrafficMetric struct {
	SentBytes uint32
	RecvBytes uint32
}

func (m RawTrafficMetric) String() string {
	return fmt.Sprintf("%v bytes sent and %v bytes received", m.SentBytes, m.RecvBytes)
}

type RawTrafficMetaData struct {
	IP   string `bson:"ip"`
	Tag  string `bson:"tag"`
	Node string `bson:"node"`
}

func (m RawTrafficMetaData) String() string {
	return fmt.Sprintf("ip: %v, tag: %v, node: %v", m.IP, m.Tag, m.Node)
}

type RawTraffic struct {
	Metric    RawTrafficMetric   `bson:"metric"`
	Meta      RawTrafficMetaData `bson:"meta"`
	ID        string             `bson:"rt_id"`
	Timestamp time.Time          `bson:"timestamp"`
}

func (t RawTraffic) String() string {
	return fmt.Sprintf("%v: %v; %v", t.Timestamp, t.Meta, t.Metric)
}

func (e *RawTrafficEvent) GetTagsForSrc() []string {
	//TODO: imple me
	portTag := fmt.Sprintf("port:%v", e.RawTrafficEventMeta.SrcPort)
	return []string{portTag}
}

func (e *RawTrafficEvent) GetTagsForDst() []string {
	//TODO: imple me
	portTag := fmt.Sprintf("port:%v", e.RawTrafficEventMeta.DstPort)
	return []string{portTag}
}
