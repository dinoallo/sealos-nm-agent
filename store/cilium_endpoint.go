package store

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	CILIUM_ENDPOINT_WORKER_COUNT = 5
)

type CiliumEndpointStore struct {
	name     string
	logger   *zap.SugaredLogger
	manager  *StoreManager
	cepCache *lru_expirable.LRU[string, *CiliumEndpoint]

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
	if s.cepCache == nil {
		return util.ErrCacheNotInited
	}
	node := s.GetCurrentNode()
	key := s.getKey(eid, node)
	createdTime := time.Now().Unix()
	if cep, ok := s.cepCache.Get(key); ok {
		newCEP := CiliumEndpoint{
			ID:          cep.ID,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: createdTime,
			DeletedTime: 0,
		}
		s.cepCache.Remove(key)
		s.cepCache.Add(key, &newCEP)
	} else {
		cep := CiliumEndpoint{
			ID:          key,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: createdTime,
			DeletedTime: 0,
		}
		s.cepCache.Add(key, &cep)
	}
	return nil
}

func (s *CiliumEndpointStore) Remove(ctx context.Context, eid int64) error {
	if s.cepCache == nil {
		return util.ErrCacheNotInited
	}
	node := s.GetCurrentNode()
	key := s.getKey(eid, node)
	deletedTime := time.Now().Unix()
	if cep, ok := s.cepCache.Get(key); ok {
		newCEP := CiliumEndpoint{
			ID:          cep.ID,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: cep.CreatedTime,
			DeletedTime: deletedTime,
		}
		s.cepCache.Remove(key)
		s.cepCache.Add(key, &newCEP)
	}
	return nil
}

func (s *CiliumEndpointStore) GetCurrentNode() string {
	s.nodeMutex.RLock()
	defer s.nodeMutex.RUnlock()
	return s.currentNode
}

func (s *CiliumEndpointStore) initCache(ctx context.Context) error {
	if err := s.setHostName(); err != nil {
		return err
	}
	p := s.manager.ps
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	s.cepCache = lru_expirable.NewLRU[string, *CiliumEndpoint](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_ENTRIES_SIZE)
	var ceps []CiliumEndpoint
	//TODO: maybe try to find all the endpoints that are not stale
	if err := p.findAll(ctx, CEPCollection, -1, ceps); err != nil {
		return err
	} else {
		for _, cep := range ceps {
			if cep.DeletedTime != 0 {
				// stale endpoint
				continue
			}
			if cep.Node == s.GetCurrentNode() {
				key := s.getKey(cep.EndpointID, cep.Node)
				s.cepCache.Add(key, &cep)
			}
		}
	}
	return nil
}

func (s *CiliumEndpointStore) onEvicted(key string, value *CiliumEndpoint) {
	if s.logger == nil {
		// !?
		return
	}
	logger := s.logger
	if s.manager == nil {
		logger.Errorf("%v", util.ErrStoreManagerNotInited)
		return
	}
	p := s.manager.ps
	if p == nil {
		logger.Errorf("%v", util.ErrPersistentStorageNotInited)
		return
	}
	if value == nil {
		return
	}
	if p != nil {
		keyField := "cep_id"
		if err := p.replaceOne(context.Background(), CEPCollection, keyField, key, *value); err != nil {
			return
		}
	} else {
		logger.Errorf("%v", util.ErrPersistentStorageNotInited)
		return
	}
}

func (s *CiliumEndpointStore) setHostName() error {
	if currentNode, err := os.Hostname(); err != nil {
		return err
	} else {
		if s.GetCurrentNode() != currentNode {
			s.logger.Infof("updating the current node to %v", currentNode)
			s.nodeMutex.Lock()
			s.currentNode = currentNode
			s.nodeMutex.Unlock()
		}
	}
	return nil
}
func (s *CiliumEndpointStore) getKey(eid int64, node string) string {
	return fmt.Sprintf("%s/%s", node, fmt.Sprint(eid))
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
	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
				if err := s.setHostName(); err != nil {
					return err
				}
			}
		}
	})
	return nil
}
