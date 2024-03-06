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
	ceps, err := s.getAllCEPsFromPersistent(ctx)
	if err != nil {
		return err
	}
	if ceps == nil {
		return nil
	}
	for _, cep := range *ceps {
		key := s.getKey(cep.EndpointID, cep.Node)
		_cep := cep
		s.cepCache.Add(key, &_cep)
	}
	return nil
}

// TODO: get only the ceps of this node with filter maybe?
func (s *CiliumEndpointStore) getAllCEPsFromPersistent(ctx context.Context) (*[]structs.CiliumEndpoint, error) {
	p := s.p
	var _ceps []structs.CiliumEndpoint
	if err := p.FindAll(ctx, s.cepColl, &_ceps); err != nil {
		return nil, err
	}
	node := s.getCurrentNode()
	var ceps []structs.CiliumEndpoint
	for _, _cep := range _ceps {
		if _cep.IsIrrelevant(node) {
			continue
		}
		ceps = append(ceps, _cep)
	}
	return &ceps, nil
}

func (s *CiliumEndpointStore) getCEPFromPersistent(ctx context.Context, eid int64) (*structs.CiliumEndpoint, error) {
	p := s.p
	var _cep structs.CiliumEndpoint
	filterKey := "endpoint_id"
	if found, err := p.FindOne(ctx, s.cepColl, filterKey, eid, &_cep); err != nil {
		return nil, err
	} else if found {
		return &_cep, nil
	}
	return nil, nil
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
	cep, err := s.getCEPFromPersistent(ctx, eid)
	if err != nil {
		return err
	}
	if cep == nil {
		return nil
	}
	cep.DeletedTime = deletedTime
	s.cepCache.Add(key, cep)
	return nil
}

func (s *CiliumEndpointStore) getCEP(ctx context.Context, eid int64) (*structs.CiliumEndpoint, error) {
	node := s.getCurrentNode()
	key := s.getKey(eid, node)
	if _cep, ok := s.cepCache.Get(key); ok {
		cep := *_cep
		return &cep, nil
	}
	cep, err := s.getCEPFromPersistent(ctx, eid)
	if err != nil {
		return nil, err
	}
	if cep == nil {
		return nil, nil
	}
	s.cepCache.Add(key, cep)
	cepCopy := *cep
	return &cepCopy, nil
}

func (s *CiliumEndpointStore) getAllCEPs(ctx context.Context) (*[]structs.CiliumEndpoint, error) {
	_ceps, err := s.getAllCEPsFromPersistent(ctx)
	if err != nil {
		return nil, err
	}
	if _ceps == nil {
		return nil, nil
	}
	var ceps []structs.CiliumEndpoint
	for _, _cep := range *_ceps {
		key := s.getKey(_cep.EndpointID, _cep.Node)
		if cachedCEP, ok := s.cepCache.Get(key); !ok {
			newCEP := _cep
			ceps = append(ceps, newCEP)
			s.cepCache.Add(key, &newCEP)
		} else {
			ceps = append(ceps, *cachedCEP)
		}
	}
	return &ceps, nil
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
