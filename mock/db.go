// a mocking database implementing DB interface, only used for the ease of testing
package mock

import (
	"context"
	"log"

	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/db/common"
)

// a very simple, unindexed database
type TestingDB struct {
}

func NewTestingDB() *TestingDB {
	return &TestingDB{}
}

func (db *TestingDB) CreateTimeSeriesColl(ctx context.Context, collName string, opts common.TimeSeriesOpts) error {
	return nil
}

func (db *TestingDB) FindColl(ctx context.Context, collName string) (bool, error) {
	return true, nil
}

// This database will return all items currently for whatever selector used
func (db *TestingDB) Get(ctx context.Context, collName string, selector common.Selector, objs any, opts common.GetOpts) error {
	// coll, err := db.GetCollection(collName)
	// if err != nil {
	// 	return err
	// }
	// coll.sMu.RLock()
	// defer coll.sMu.RUnlock()
	// _objs, ok := (objs).(*[]any)
	// if !ok {
	// 	return fmt.Errorf("objs invalid")
	// }
	// for _, obj := range coll.s {
	// 	*_objs = append(*_objs, obj)
	// }
	return nil
}

func (db *TestingDB) GetOne(ctx context.Context, collName string, selector common.Selector, obj any) (bool, error) {
	return true, nil
}

// If the database is full, then this function won't do anything and will report an error
func (db *TestingDB) Insert(ctx context.Context, collName string, objs []any) error {
	for _, obj := range objs {
		log.Printf("%+v", obj)
	}
	// coll, err := db.GetCollection(collName)
	// if err != nil {
	// 	return err
	// }
	// coll.sMu.Lock()
	// defer coll.sMu.Unlock()
	// coll.itemCountMu.Lock()
	// defer coll.itemCountMu.Unlock()
	// for _, obj := range objs {
	// 	if coll.itemCount == db.MaxItems {
	// 		return fmt.Errorf("the database is full")
	// 	}
	// 	coll.s[coll.itemCount] = obj
	// 	coll.itemCount++
	// }
	return nil
}

func (db *TestingDB) ReplaceOne(ctx context.Context, collName string, selector common.Selector, replacement any) error {
	return nil
}
