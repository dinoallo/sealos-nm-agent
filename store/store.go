package store

import (
	"context"
	"sync"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Store interface {
	getName() string
	initCache(ctx context.Context) error
	setManager(manager *StoreManager) error
	launch(ctx context.Context, eg *errgroup.Group, workerCount int) error
}

type StoreManager struct {
	logger     *zap.SugaredLogger
	ps         *persistent
	stores     map[int]Store
	storeCount int

	storesMu sync.Mutex
}

func NewStoreManager(cred DBCred, baseLogger *zap.SugaredLogger) (*StoreManager, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	var p *persistent
	if p = newPersistent(cred); p == nil {
		return nil, util.ErrPersistentStorageNotInited
	}
	stores := make(map[int]Store)
	storeCount := 0

	return &StoreManager{
		logger:     baseLogger.With(zap.String("component", "store_manager")),
		ps:         p,
		stores:     stores,
		storeCount: storeCount,
		storesMu:   sync.Mutex{},
	}, nil
}

func (s *StoreManager) RegisterStore(store Store) error {
	log := s.logger
	if log == nil {
		return util.ErrLoggerNotInited
	}
	s.storesMu.Lock()
	defer s.storesMu.Unlock()
	s.stores[s.storeCount] = store
	s.storeCount++
	if err := store.setManager(s); err != nil {
		return err
	}
	log.Infof("manager for store %v successfully set", store.getName())
	return nil
}

func (s *StoreManager) Launch(ctx context.Context, workerCount int) error {
	log := s.logger
	if log == nil {
		return util.ErrLoggerNotInited
	}
	log.Infof("launching the store manager...")
	log.Infof("connecting to the persistent storage...")
	if s.ps == nil {
		return util.ErrPersistentStorageNotInited
	}
	if err := s.ps.connect(ctx); err != nil {
		return err
	}
	log.Info("persistent storage successfully connected")
	ok := make(chan bool, 1)
	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		<-ok
		return nil
	})
	go func() {
		// wait for cleaning up
		defer s.ps.disconnect(context.Background())
		if err := eg.Wait(); err != nil {
			log.Errorf("%v", err)
		}
	}()

	log.Infof("initializing and launch each store...")
	// initialize and launch each store
	for _, store := range s.stores {
		name := store.getName()
		if err := store.initCache(egCtx); err != nil {
			return err
		}
		log.Infof("cache for store %v successfully initialized", name)
		if err := store.launch(egCtx, eg, workerCount); err != nil {
			return err
		}
		log.Infof("store %v successfully launched", name)
	}
	ok <- true

	return nil
}
