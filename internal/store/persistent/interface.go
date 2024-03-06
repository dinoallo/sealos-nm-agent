package persistent

import (
	"context"
	"sync"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"golang.org/x/sync/errgroup"
)

type PersistentInterface struct {
	h     *Persistent
	mu    *sync.RWMutex
	ready bool
}

func NewPersistentInterface(p PersistentParam, cfg conf.PersistentStorageConfig) *PersistentInterface {
	h := newPersistent(p, cfg)
	return &PersistentInterface{
		h:     h,
		mu:    &sync.RWMutex{},
		ready: false,
	}
}

// concurrently safe persistent storage operations
func (s *PersistentInterface) FindColl(ctx context.Context, coll store.Coll) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return false, util.ErrPersistentStorageNotReady
	}
	return s.h.findCollection(ctx, coll)
}

func (s *PersistentInterface) CreateTimeSeriesColl(ctx context.Context, coll store.Coll, timeField string, metaField string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrPersistentStorageNotReady
	}
	return s.h.createTimeSeriesColl(ctx, coll, timeField, &metaField)
}

func (s *PersistentInterface) FindPartialTTLIndex(ctx context.Context, coll store.Coll, ptiName string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return false, util.ErrPersistentStorageNotReady
	}
	return s.h.findPartialTTLIndex(ctx, coll, ptiName)
}

func (s *PersistentInterface) CreatePartialTTLIndex(ctx context.Context, coll store.Coll, ptiName string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrPersistentStorageNotReady
	}
	return s.h.createPartialTTLIndex(ctx, coll, ptiName)
}

func (s *PersistentInterface) FindOne(ctx context.Context, coll store.Coll, filterKey string, filterValue any, obj any) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return false, util.ErrPersistentStorageNotReady
	}
	return s.h.findOne(ctx, coll, filterKey, filterValue, obj)
}
func (s *PersistentInterface) FindAll(ctx context.Context, coll store.Coll, items any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrPersistentStorageNotReady
	}
	return s.h.findAll(ctx, coll, -1, items)
}

func (s *PersistentInterface) InsertMany(ctx context.Context, coll store.Coll, buf []any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrPersistentStorageNotReady
	}
	return s.h.insertMany(ctx, coll, buf)
}

func (s *PersistentInterface) ReplaceOne(ctx context.Context, coll store.Coll, keyField string, key string, value any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notReady() {
		return util.ErrPersistentStorageNotReady
	}
	return s.h.replaceOne(ctx, coll, keyField, key, value)
}

func (s *PersistentInterface) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.h.connect(ctx); err != nil {
		return err
	}
	s.ready = true
	return nil
}

func (s *PersistentInterface) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = false
	//TODO: set up timeout
	if err := s.h.disconnect(ctx); err != nil {
		return err
	}
	return nil
}

func (s *PersistentInterface) notReady() bool {
	return !s.ready
}
