package cilium_endpoint

import (
	"context"
	"sync"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"golang.org/x/sync/errgroup"
)

type CiliumEndpointStoreInterface struct {
	h     *CiliumEndpointStore
	mu    *sync.RWMutex
	ready bool
}

func NewCiliumEndpointStoreInterface(param CiliumEndpointStoreParam, cfg conf.CiliumEndpointStoreConfig) *CiliumEndpointStoreInterface {
	h := newCiliumEndpointStore(param, cfg)
	return &CiliumEndpointStoreInterface{
		h:     h,
		mu:    &sync.RWMutex{},
		ready: false,
	}
}

func (s *CiliumEndpointStoreInterface) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h.setUpCache()
	if err := s.h.initCache(ctx); err != nil {
		return err
	}
	if err := s.h.init(ctx); err != nil {
		return err
	}
	s.ready = true
	return nil
}

func (s *CiliumEndpointStoreInterface) Create(ctx context.Context, eid int64) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrCiliumEndpointStoreNotReady
	}
	return s.h.create(ctx, eid)
}

func (s *CiliumEndpointStoreInterface) RemoveCEP(ctx context.Context, eid int64) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrCiliumEndpointStoreNotReady
	}
	return s.h.removeCEP(ctx, eid)
}

func (s *CiliumEndpointStoreInterface) getCurrentNode() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return "", util.ErrCiliumEndpointStoreNotReady
	}
	return s.h.getCurrentNode(), nil
}

func (s *CiliumEndpointStoreInterface) FindCEP(ctx context.Context, eid int64) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return false, util.ErrCiliumEndpointStoreNotReady
	}
	if cep, err := s.h.getCEP(ctx, eid); err != nil {
		return false, err
	} else {
		return (cep != nil), nil
	}
}

func (s *CiliumEndpointStoreInterface) GetAllCEPs(ctx context.Context, ceps *[]structs.CiliumEndpoint) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrCiliumEndpointStoreNotReady
	}
	return s.h.getAllCEPs(ctx, ceps)
}

func (s *CiliumEndpointStoreInterface) notReady() bool {
	return !s.ready
}
