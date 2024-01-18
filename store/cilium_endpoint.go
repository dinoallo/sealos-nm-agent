package store

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	CILIUM_ENDPOINT_WORKER_COUNT = 5
)

type CiliumEndpointStore struct {
	name    string
	logger  *zap.SugaredLogger
	manager *StoreManager

	nodeMutex   sync.RWMutex
	currentNode string
}

func NewCiliumEndpointStore(baseLogger *zap.SugaredLogger) (*CiliumEndpointStore, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	return &CiliumEndpointStore{
		name:        "cilium_endpoints",
		logger:      baseLogger.With(zap.String("component", "cilium_endpoint_store")),
		nodeMutex:   sync.RWMutex{},
		currentNode: "",
	}, nil
}

func (s *CiliumEndpointStore) GetAll(ctx context.Context, ceps *[]CiliumEndpoint) (bool, error) {
	if ceps == nil {
		return false, fmt.Errorf("a slice of CiliumEndpoint should be created")
	}
	if s.manager == nil {
		return false, util.ErrStoreManagerNotInited
	}
	p := s.manager.ps
	if p == nil {
		return false, util.ErrPersistentStorageNotInited
	}
	found := false
	if err := p.findAll(ctx, CEPCollection, -1, ceps); err != nil {
		return false, err
	} else {
		if len(*ceps) > 0 {
			found = true
		}
	}
	return found, nil
}

func (s *CiliumEndpointStore) Create(ctx context.Context, eid int64) error {
	if s.manager == nil {
		return util.ErrStoreManagerNotInited
	}
	p := s.manager.ps
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	createdTime := time.Now().Unix()
	cep := CiliumEndpoint{
		EndpointID:  eid,
		Node:        s.GetCurrentNode(),
		CreatedTime: createdTime,
	}
	if err := p.replaceOne(ctx, CEPCollection, "endpoint_id", fmt.Sprint(eid), cep); err != nil {
		return err
	}
	return nil
}

func (s *CiliumEndpointStore) Remove(ctx context.Context, eid int64) error {
	if s.manager == nil {
		return util.ErrStoreManagerNotInited
	}
	p := s.manager.ps
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	if err := p.deleteOne(ctx, CEPCollection, "endpoint_id", fmt.Sprint(eid)); err != nil {
		return err
	}
	return nil
}

func (s *CiliumEndpointStore) GetCurrentNode() string {
	s.nodeMutex.RLock()
	defer s.nodeMutex.RUnlock()
	return s.currentNode
}

func (s *CiliumEndpointStore) initCache(ctx context.Context) error {
	return nil
}

func (s *CiliumEndpointStore) setManager(manager *StoreManager) error {
	if manager == nil {
		return util.ErrStoreManagerNotInited
	}
	s.manager = manager
	return nil
}

func (s *CiliumEndpointStore) getName() string {
	return s.name
}

func (s *CiliumEndpointStore) launch(ctx context.Context, eg *errgroup.Group) error {
	for i := 0; i < CILIUM_ENDPOINT_WORKER_COUNT; i++ {
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				default:
					if currentNode, err := os.Hostname(); err != nil {
						return err
					} else {
						if s.GetCurrentNode() != currentNode {
							s.logger.Infof("updateing the current node to %v", currentNode)
							s.nodeMutex.Lock()
							s.currentNode = currentNode
							s.nodeMutex.Unlock()
						}
					}
				}
			}
		})
	}
	return nil
}
