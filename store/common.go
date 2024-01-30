package store

import (
	"time"
)

type TrafficDirection uint32

const (
	CACHE_ENTRIES_SIZE = 1e6
	CACHE_EXPIRED_TIME = time.Millisecond * 100
)
const (
	TRAFFIC_DIR_UNKNOWN TrafficDirection = iota
	TRAFFIC_DIR_V4_INGRESS
	TRAFFIC_DIR_V4_EGRESS
	TRAFFIC_DIR_V6_INGRESS
	TRAFFIC_DIR_V6_EGRESS
)

type CollType int

type Coll struct {
	T      CollType
	Prefix string
}

const (
	COLL_TYPE_TR CollType = iota
	COLL_TYPE_CEP
)

var (
	TRCollection  Coll = Coll{T: COLL_TYPE_TR, Prefix: "traffic_reports"}
	CEPCollection Coll = Coll{T: COLL_TYPE_CEP, Prefix: "cilium_endpoints"}
)
