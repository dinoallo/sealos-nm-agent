package mock

import (
	"context"
	"log"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
)

type DummyPodTrafficStore struct {
	podAddr string
}

func NewDummyPodTrafficStore(podAddr string) *DummyPodTrafficStore {
	return &DummyPodTrafficStore{
		podAddr: podAddr,
	}
}

func (pts *DummyPodTrafficStore) Update(ctx context.Context, hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error {
	if meta.PodAddress != pts.podAddr {
		return nil
	}
	log.Printf("meta: %+v; metric: %+v", meta, metric)
	return nil
}

type DummyTrafficStore struct {
	MarkedPodAddrForPodTraffic   string
	MarkedRemoteIPForHostTraffic string
}

func (s *DummyTrafficStore) UpdatePodTraffic(ctx context.Context, hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error {
	if s.MarkedPodAddrForPodTraffic == "" || meta.PodAddress != s.MarkedPodAddrForPodTraffic {
		return nil
	}
	log.Printf("meta: %+v; metric: %+v", meta, metric)
	return nil
}

func (s *DummyTrafficStore) UpdateHostTraffic(ctx context.Context, hash string, meta structs.HostTrafficMeta, metric structs.HostTrafficMetric) error {
	if s.MarkedRemoteIPForHostTraffic == "" || meta.RemoteIP != s.MarkedRemoteIPForHostTraffic {
		return nil
	}
	log.Printf("meta: %+v; metric: %+v", meta, metric)
	return nil
}
