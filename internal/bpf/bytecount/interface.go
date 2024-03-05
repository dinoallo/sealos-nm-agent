package bytecount

import (
	"context"
	"sync"

	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"golang.org/x/sync/errgroup"
)

type BytecountFactoryInterface struct {
	h     *BytecountFactory
	mu    *sync.RWMutex
	ready bool
}

func NewBytecountFactoryInterface(p BytecountFactoryParam, cfg conf.BytecountFactoryConfig) *BytecountFactoryInterface {
	h := newBytecountFactory(p, cfg)
	return &BytecountFactoryInterface{
		h:     h,
		mu:    &sync.RWMutex{},
		ready: false,
	}
}

func (s *BytecountFactoryInterface) CreateCounter(ctx context.Context, eid int64, dir consts.TrafficDirection) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrBytecountFactoryNotReady
	}
	return s.h.createCounter(ctx, eid, dir)
}

func (s *BytecountFactoryInterface) RemoveCounter(ctx context.Context, eid int64, dir consts.TrafficDirection) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrBytecountFactoryNotReady
	}
	return s.h.removeCounter(ctx, eid, dir)
}

func (s *BytecountFactoryInterface) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.h.setIPAddrs(); err != nil {
		return err
	}
	if err := s.h.setNativeEndian(); err != nil {
		return err
	}
	if err := s.h.initObjs(ctx); err != nil {
		return err
	}
	if err := s.h.initCounter(ctx); err != nil {
		return err
	}
	mainEg.Go(func() error {
		return s.h.startProcessor(ctx)
	})
	mainEg.Go(func() error {
		return s.h.startReader(ctx)
	})
	s.ready = true
	return nil
}

func (s *BytecountFactoryInterface) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = false
	//TODO: set up timeout
	if err := s.h.stop(ctx); err != nil {
		return err
	}
	return nil
}

func (s *BytecountFactoryInterface) notReady() bool {
	return !s.ready
}
