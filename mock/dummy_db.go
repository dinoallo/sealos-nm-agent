package mock

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-library/pkg/db/common"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

type DummyDB struct {
	log.Logger
}

func (db *DummyDB) CreateTimeSeriesColl(ctx context.Context, collName string, opts common.TimeSeriesOpts) error {
	return nil
}
func (db *DummyDB) FindColl(ctx context.Context, collName string) (bool, error) {
	return true, nil
}
func (db *DummyDB) Get(ctx context.Context, collName string, selector common.Selector, objs any, opts common.GetOpts) error {
	return nil
}
func (db *DummyDB) GetOne(ctx context.Context, collName string, selector common.Selector, obj any) (bool, error) {
	return true, nil
}
func (db *DummyDB) Insert(ctx context.Context, collName string, objs []any) error {
	for _, obj := range objs {
		db.Infof("insert: %v", obj)
	}
	return nil
}
func (db *DummyDB) ReplaceOne(ctx context.Context, collName string, selector common.Selector, replacement any) error {
	return nil
}
