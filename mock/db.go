// a mocking database implementing DB interface, only used for the ease of testing
package mock

import (
	"context"
	"log"

	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db"
)

// a very simple, unindexed database
type TestingDB struct {
}

func NewTestingDB() *TestingDB {
	return &TestingDB{}
}

func (db *TestingDB) CreateTimeSeriesColl(ctx context.Context, collName string, opts db.TimeSeriesOpts) error {
	return nil
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
