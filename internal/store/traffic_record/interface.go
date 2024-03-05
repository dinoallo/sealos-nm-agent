package traffic_record

import (
	"context"
	"sync"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"golang.org/x/sync/errgroup"
)

type TrafficRecordStoreInterface struct {
	h     *TrafficRecordStore
	mu    *sync.RWMutex
	ready bool
}

func NewTrafficRecordStoreInterface(param TrafficRecordStoreParam, cfg conf.TrafficRecordStoreConfig) *TrafficRecordStoreInterface {
	h := newTrafficRecordStore(param, cfg)
	return &TrafficRecordStoreInterface{
		h:     h,
		mu:    &sync.RWMutex{},
		ready: false,
	}
}

func (s *TrafficRecordStoreInterface) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	// TODO: check store param
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h.InitSyncQueue()
	if err := s.h.Init(ctx); err != nil {
		return err
	}
	mainEg.Go(func() error {
		return s.h.StartWorker(ctx)
	})
	mainEg.Go(func() error {
		return s.h.StartRecver(ctx)
	})
	s.ready = true
	return nil
}

func (s *TrafficRecordStoreInterface) AddTrafficReport(ctx context.Context, report *structs.TrafficReport) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrTrafficMonitorStoreNotReady
	}
	return s.h.addTrafficReport(ctx, report)
}

func (s *TrafficRecordStoreInterface) notReady() bool {
	return !s.ready
}
