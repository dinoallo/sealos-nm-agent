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

type DummyHostTrafficStore struct {
	hostAddr string
}

func NewDummyHostTrafficStore(hostAddr string) *DummyHostTrafficStore {
	return &DummyHostTrafficStore{
		hostAddr: hostAddr,
	}
}

func (hts *DummyHostTrafficStore) Update(ctx context.Context, hash string, meta structs.HostTrafficMeta, metric structs.HostTrafficMetric) error {
	if meta.IP != hts.hostAddr {
		return nil
	}
	log.Printf("meta: %+v; metric: %+v", meta, metric)
	return nil
}
