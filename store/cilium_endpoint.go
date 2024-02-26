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
	CILIUM_ENDPOINT_PTI_NAME     = "stale"
)

type CiliumEndpointStore struct {
	name        string
	logger      *zap.SugaredLogger
	p           *persistent
	cepCache    *lru_expirable.LRU[string, *CiliumEndpoint]
	nodeMutex   sync.RWMutex
	currentNode string
}

func NewCiliumEndpointStore(baseLogger *zap.SugaredLogger, p *persistent) (*CiliumEndpointStore, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	name := "cilium_endpoint_store"
	return &CiliumEndpointStore{name: name,
		p:           p,
		logger:      baseLogger.With(zap.String("component", name)),
		nodeMutex:   sync.RWMutex{},
		currentNode: "",
	}, nil
}

func (s *CiliumEndpointStore) GetName() string {
	return s.name
}

func (s *CiliumEndpointStore) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	s.cepCache = lru_expirable.NewLRU[string, *CiliumEndpoint](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_ENTRIES_SIZE)
	p := s.p
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	if found, err := p.findPartialTTLIndex(ctx, CEPCollection, CILIUM_ENDPOINT_PTI_NAME); err != nil {
		return err
	} else if !found {
		if err := p.setupCiliumEndpointAutoDeletion(ctx, CEPCollection, CILIUM_ENDPOINT_PTI_NAME); err != nil {
			if err != util.ErrPartialTTLIndexAlreadyExists {
				return err
			}
		}
	}
	// set the hostname for the first time
	if err := s.setHostName(); err != nil {
		return err
	}
	mainEg.Go(func() error {
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

func (s *CiliumEndpointStore) Stop(ctx context.Context) error {
	return nil
}

func (s *CiliumEndpointStore) GetAll(ctx context.Context, ceps *[]CiliumEndpoint) (bool, error) {
	if ceps == nil {
		return false, fmt.Errorf("a slice of CiliumEndpoint should be created")
	}
	p := s.p
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

func (s *CiliumEndpointStore) Find(ctx context.Context, eid int64) (bool, error) {
	found := false
	if s.cepCache == nil {
		return false, util.ErrCacheNotInited
	}
	node := s.GetCurrentNode()
	key := s.getKey(eid, node)
	if _, ok := s.cepCache.Get(key); ok {
		found = true
	}
	return found, nil
}

func (s *CiliumEndpointStore) Create(ctx context.Context, eid int64) error {
	if s.cepCache == nil {
		return util.ErrCacheNotInited
	}
	node := s.GetCurrentNode()
	key := s.getKey(eid, node)
	createdTime := time.Now()
	if cep, ok := s.cepCache.Get(key); ok {
		newCEP := CiliumEndpoint{
			ID:          cep.ID,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: createdTime,
		}
		s.cepCache.Remove(key)
		s.cepCache.Add(key, &newCEP)
	} else {
		cep := CiliumEndpoint{
			ID:          key,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: createdTime,
		}
		s.cepCache.Add(key, &cep)
	}
	return nil
}

func (s *CiliumEndpointStore) Remove(ctx context.Context, cep *CiliumEndpoint) error {
	if s.cepCache == nil {
		return util.ErrCacheNotInited
	}
	node := s.GetCurrentNode()
	key := s.getKey(cep.EndpointID, node)
	deletedTime := time.Now()
	newCEP := CiliumEndpoint{
		ID:          key,
		EndpointID:  cep.EndpointID,
		Node:        node,
		CreatedTime: cep.CreatedTime,
		DeletedTime: deletedTime,
	}
	if _, ok := s.cepCache.Get(key); ok {
		s.cepCache.Remove(key)
	}
	s.cepCache.Add(key, &newCEP)
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
	p := s.p
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	s.cepCache = lru_expirable.NewLRU[string, *CiliumEndpoint](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_ENTRIES_SIZE)
	var ceps []CiliumEndpoint
	//TODO: maybe try to find all the endpoints that are not stale
	if err := p.findAll(ctx, CEPCollection, -1, &ceps); err != nil {
		return err
	} else {
		for _, cep := range ceps {
			if cep.DeletedTime.IsZero() {
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
	p := s.p
	if p == nil {
		logger.Errorf("%v", util.ErrPersistentStorageNotInited)
		return
	}
	if value == nil {
		return
	}
	if p != nil {
		keyField := "cep_id"
		ctx, cancel := context.WithTimeout(context.Background(), DB_CONNECTION_TIMEOUT)
		defer cancel()
		if err := p.replaceOne(ctx, CEPCollection, keyField, key, *value); err != nil {
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
