package store

import (
	"sync/atomic"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
)

type PodMetric struct {
	SentBytes atomic.Uint64
	RecvBytes atomic.Uint64
}

type HostMetric struct {
	SentBytes atomic.Uint64
	RecvBytes atomic.Uint64
}

type PodTrafficAccount struct {
	Hash string
	structs.PodTrafficMeta
	PodMetric
	Since time.Time
}

type HostTrafficAccount struct {
	Hash string
	structs.HostTrafficMeta
	HostMetric
	Since time.Time
}

func NewPodTrafficAccount(hash string, meta structs.PodTrafficMeta) *PodTrafficAccount {
	return &PodTrafficAccount{
		Hash:           hash,
		PodTrafficMeta: meta,
		PodMetric: PodMetric{
			SentBytes: atomic.Uint64{},
			RecvBytes: atomic.Uint64{},
		},
		Since: time.Now(),
	}
}

func NewHostTrafficAccount(hash string, meta structs.HostTrafficMeta) *HostTrafficAccount {
	return &HostTrafficAccount{
		Hash:            hash,
		HostTrafficMeta: meta,
		HostMetric: HostMetric{
			SentBytes: atomic.Uint64{},
			RecvBytes: atomic.Uint64{},
		},
		Since: time.Now(),
	}
}

func (a *PodTrafficAccount) ConvertToData() []*structs.PodTraffic {
	podTraffic := structs.PodTraffic{
		PodTrafficMeta: a.PodTrafficMeta,
		SentBytes:      a.PodMetric.SentBytes.Load(),
		RecvBytes:      a.PodMetric.RecvBytes.Load(),
		Timestamp:      time.Now(),
	}
	return []*structs.PodTraffic{&podTraffic}
}

func (a *HostTrafficAccount) ConvertToData() []*structs.HostTraffic {
	hostTraffic := structs.HostTraffic{
		HostTrafficMeta: a.HostTrafficMeta,
		HostTrafficMetric: structs.HostTrafficMetric{
			SentBytes: a.HostMetric.SentBytes.Load(),
			RecvBytes: a.HostMetric.RecvBytes.Load(),
		},
		Timestamp: time.Now(),
	}
	return []*structs.HostTraffic{&hostTraffic}
}

func (a *PodTrafficAccount) GetHash() string {
	return a.Hash
}

func (a *HostTrafficAccount) GetHash() string {
	return a.Hash
}
