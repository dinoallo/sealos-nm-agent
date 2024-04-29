// a mocking database implementing DB interface, only used for the ease of testing
package mock

import (
	"context"
	"fmt"
	"sync"

	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/common"
)

type TestingDBConfig struct {
	MaxItems int
}

type Collection struct {
	itemCount   int
	itemCountMu sync.RWMutex
	s           map[int]any
	sMu         sync.RWMutex
}

func NewCollection(maxItems int) *Collection {
	return &Collection{
		itemCount:   0,
		itemCountMu: sync.RWMutex{},
		s:           make(map[int]any, maxItems),
		sMu:         sync.RWMutex{},
	}
}

// a very simple, unindexed database
type TestingDB struct {
	collections sync.Map
	TestingDBConfig
}

func NewTestingDB(cfg TestingDBConfig) *TestingDB {
	return &TestingDB{
		collections:     sync.Map{},
		TestingDBConfig: cfg,
	}
}

func (db *TestingDB) GetCollection(collName string) (*Collection, error) {
	newColl := NewCollection(db.MaxItems)
	_coll, loaded := db.collections.LoadOrStore(collName, newColl)
	if loaded {
		coll, ok := (_coll).(*Collection)
		if !ok {
			return nil, fmt.Errorf("invalid collection?")
		}
		return coll, nil
	}
	return newColl, nil
}

func (db *TestingDB) CreateTimeSeriesColl(ctx context.Context, collName string, opts common.TimeSeriesOpts) error {
	return nil
}

func (db *TestingDB) FindColl(ctx context.Context, collName string) (bool, error) {
	return true, nil
}

// This database will return all items currently for whatever selector used
func (db *TestingDB) Get(ctx context.Context, collName string, selector common.Selector, objs any, opts common.GetOpts) error {
	coll, err := db.GetCollection(collName)
	if err != nil {
		return err
	}
	coll.sMu.RLock()
	defer coll.sMu.RUnlock()
	_objs, ok := (objs).(*[]any)
	if !ok {
		return fmt.Errorf("objs invalid")
	}
	for _, obj := range coll.s {
		*_objs = append(*_objs, obj)
	}
	return nil
}

func (db *TestingDB) GetOne(ctx context.Context, collName string, selector common.Selector, obj any) (bool, error) {
	return true, nil
}

// If the database is full, then this function won't do anything and will report an error
func (db *TestingDB) Insert(ctx context.Context, collName string, objs []any) error {
	coll, err := db.GetCollection(collName)
	if err != nil {
		return err
	}
	coll.sMu.Lock()
	defer coll.sMu.Unlock()
	coll.itemCountMu.Lock()
	defer coll.itemCountMu.Unlock()
	for _, obj := range objs {
		if coll.itemCount == db.MaxItems {
			return fmt.Errorf("the database is full")
		}
		coll.s[coll.itemCount] = obj
		coll.itemCount++
	}
	return nil
}

func (db *TestingDB) ReplaceOne(ctx context.Context, collName string, selector common.Selector, replacement any) error {
	return nil
}
