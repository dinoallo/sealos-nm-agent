package cilium_endpoint

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
)

type CiliumEndpointStore struct {
	name        string
	logger      *zap.SugaredLogger
	cepCache    *lru_expirable.LRU[string, *structs.CiliumEndpoint]
	nodeMutex   sync.RWMutex
	currentNode string

	param   CiliumEndpointStoreParam
	cfg     conf.CiliumEndpointStoreConfig
	p       *persistent.PersistentInterface
	cepColl store.Coll
}

func newCiliumEndpointStore(param CiliumEndpointStoreParam, cfg conf.CiliumEndpointStoreConfig) *CiliumEndpointStore {
	cepColl := store.Coll{
		T:    store.COLL_TYPE_CEP,
		Name: cfg.CiliumEndpointColl,
	}
	name := "cilium_endpoint_store"
	return &CiliumEndpointStore{name: name,
		logger:      param.ParentLogger.With(zap.String("component", name)),
		nodeMutex:   sync.RWMutex{},
		currentNode: "",
		param:       param,
		cfg:         cfg,
		p:           param.P,
		cepColl:     cepColl,
	}
}

func (s *CiliumEndpointStore) init(ctx context.Context) error {
	p := s.p
	var ttlExists bool
	var err error
	for {
		ttlExists, err = p.FindPartialTTLIndex(ctx, s.cepColl, s.cfg.PartialTTLIndex)
		if err == nil {
			break
		} else if err == util.ErrPersistentStorageNotReady {
			time.Sleep(time.Millisecond * 100)
		} else {
			return err
		}
	}
	if !ttlExists {
		for {
			err = p.CreatePartialTTLIndex(ctx, s.cepColl, s.cfg.PartialTTLIndex)
			if err == nil {
				break
			} else if err == util.ErrPersistentStorageNotReady {
				time.Sleep(time.Millisecond * 100)
			} else if err == util.ErrPartialTTLIndexAlreadyExists {
				break
			} else {
				return err
			}
		}
	}
	// set current node name for the first time
	node, err := os.Hostname()
	if err != nil {
		return err
	}
	if err := s.setCurrentNode(node); err != nil {
		return err
	}
	return nil
}

func (s *CiliumEndpointStore) setUpCache() {
	s.cepCache = lru_expirable.NewLRU[string, *structs.CiliumEndpoint](s.cfg.MaxEndpointEntriesSize, s.onEvicted, time.Duration(s.cfg.EndpointSyncPeriod)*time.Second)
}

func (s *CiliumEndpointStore) initCache(ctx context.Context) error {
	var ceps []structs.CiliumEndpoint
	if found, err := s.getAllCEPsFromPersistent(ctx, &ceps); err != nil {
		return err
	} else if found {
		node := s.getCurrentNode()
		for _, cep := range ceps {
			if !cep.DeletedTime.IsZero() || cep.Node != node {
				continue
			}
			key := s.getKey(cep.EndpointID, cep.Node)
			_cep := cep
			s.cepCache.Add(key, &_cep)
		}
	}
	return nil
}

func (s *CiliumEndpointStore) getAllCEPs(ctx context.Context, ceps *[]structs.CiliumEndpoint) error {
	if ceps == nil {
		return nil
	}
	var _ceps []structs.CiliumEndpoint
	if found, err := s.getAllCEPsFromPersistent(ctx, &_ceps); err != nil {
		return err
	} else if found {
		node := s.getCurrentNode()
		for _, cep := range _ceps {
			if !cep.DeletedTime.IsZero() || cep.Node != node {
				continue
			}
			key := s.getKey(cep.EndpointID, cep.Node)
			if cachedCEP, ok := s.cepCache.Get(key); !ok {
				newCEP := cep
				s.cepCache.Add(key, &newCEP)
				(*ceps) = append((*ceps), newCEP)
			} else {
				(*ceps) = append((*ceps), *cachedCEP)
			}
		}
	}
	return nil
}

// TODO: get only the ceps of this node
func (s *CiliumEndpointStore) getAllCEPsFromPersistent(ctx context.Context, ceps *[]structs.CiliumEndpoint) (bool, error) {
	if ceps == nil {
		return false, fmt.Errorf("a slice of CiliumEndpoint should be created")
	}
	p := s.p
	found := false
	if err := p.FindAll(ctx, s.cepColl, ceps); err != nil {
		return false, err
	} else {
		if len(*ceps) > 0 {
			found = true
		}
	}
	return found, nil
}

func (s *CiliumEndpointStore) getCEPFromPersistent(ctx context.Context, eid int64, cep *structs.CiliumEndpoint) (bool, error) {
	p := s.p
	var _cep structs.CiliumEndpoint
	filterKey := "endpoint_id"
	if found, err := p.FindOne(ctx, s.cepColl, filterKey, eid, &_cep); err != nil {
		return false, err
	} else if found {
		*cep = _cep
		return found, nil
	}
	return false, nil
}

func (s *CiliumEndpointStore) create(ctx context.Context, eid int64) error {
	if s.cepCache == nil {
		return util.ErrCacheNotInited
	}
	node := s.getCurrentNode()
	key := s.getKey(eid, node)
	createdTime := time.Now()
	if cep, ok := s.cepCache.Get(key); ok {
		newCEP := structs.CiliumEndpoint{
			ID:          cep.ID,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: createdTime,
		}
		s.cepCache.Remove(key)
		s.cepCache.Add(key, &newCEP)
	} else {
		cep := structs.CiliumEndpoint{
			ID:          key,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: createdTime,
		}
		s.cepCache.Add(key, &cep)
	}
	return nil
}

func (s *CiliumEndpointStore) removeCEP(ctx context.Context, eid int64) error {
	node := s.getCurrentNode()
	key := s.getKey(eid, node)
	deletedTime := time.Now()
	if cep, ok := s.cepCache.Get(key); ok {
		newCEP := structs.CiliumEndpoint{
			ID:          key,
			EndpointID:  eid,
			Node:        node,
			CreatedTime: cep.CreatedTime,
			DeletedTime: deletedTime,
		}
		s.cepCache.Remove(key)
		s.cepCache.Add(key, &newCEP)
		return nil
	}
	var cep structs.CiliumEndpoint
	if found, err := s.getCEPFromPersistent(ctx, eid, &cep); err != nil {
		return err
	} else if found {
		cep.DeletedTime = deletedTime
		s.cepCache.Add(key, &cep)
	}
	return nil
}

func (s *CiliumEndpointStore) getCEP(ctx context.Context, eid int64) (*structs.CiliumEndpoint, error) {
	node := s.getCurrentNode()
	key := s.getKey(eid, node)
	var cep structs.CiliumEndpoint
	if _cep, ok := s.cepCache.Get(key); ok {
		cep = *_cep
		return &cep, nil
	}
	if found, err := s.getCEPFromPersistent(ctx, eid, &cep); err != nil {
		return nil, err
	} else if found {
		s.cepCache.Add(key, &cep)
		return &cep, nil
	}
	return nil, nil
}

func (s *CiliumEndpointStore) getCurrentNode() string {
	s.nodeMutex.RLock()
	defer s.nodeMutex.RUnlock()
	return s.currentNode
}

func (s *CiliumEndpointStore) onEvicted(key string, value *structs.CiliumEndpoint) {
	if s.logger == nil {
		// !?
		return
	}
	logger := s.logger
	p := s.p
	if value == nil {
		return
	}
	keyField := "cep_id"
	if err := p.ReplaceOne(context.Background(), s.cepColl, keyField, key, *value); err != nil {
		logger.Errorf("unable to replace: %v", err)
		return
	}
}

func (s *CiliumEndpointStore) setCurrentNode(node string) error {
	s.nodeMutex.Lock()
	defer s.nodeMutex.Unlock()
	s.currentNode = node
	return nil
}

func (s *CiliumEndpointStore) getKey(eid int64, node string) string {
	return fmt.Sprintf("%s/%s", node, fmt.Sprint(eid))
}
