package store

import (
	"time"
)

type TrafficDirection uint32

const (
	CACHE_ENTRIES_SIZE = 256
	CACHE_EXPIRED_TIME = time.Second * 3
)
const (
	V4Ingress TrafficDirection = iota
	V4Egress
	V6Ingress
	V6Egress
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
