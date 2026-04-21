// a mocking database implementing DB interface, only used for the ease of testing
package mock

import (
	"context"
	"log"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db"
)

// a very simple, unindexed database
type TestingDB struct {
	SupportsTimeSeriesColl bool
}

func NewTestingDB() *TestingDB {
	return &TestingDB{
		SupportsTimeSeriesColl: true,
	}
}

func (db *TestingDB) CreateColl(ctx context.Context, collName string, opts db.CreateCollOpts) error {
	return nil
}

func (db *TestingDB) CreateTimeSeriesColl(ctx context.Context, collName string, opts db.TimeSeriesOpts) error {
	return nil
}

func (db *TestingDB) SupportsTimeSeries(ctx context.Context) (bool, error) {
	return db.SupportsTimeSeriesColl, nil
}

func (db *TestingDB) FindColl(ctx context.Context, collName string) (bool, error) {
	return true, nil
}

// If the database is full, then this function won't do anything and will report an error
func (db *TestingDB) Insert(ctx context.Context, collName string, objs []any) error {
	for _, obj := range objs {
		log.Printf("%+v", obj)
	}
	return nil
}

func (db *TestingDB) DeleteExpiredBefore(ctx context.Context, collName string, timeField string, expireBefore time.Time) (int64, error) {
	log.Printf("delete expired docs from coll=%s where %s < %s", collName, timeField, expireBefore.Format(time.RFC3339))
	return 0, nil
}
