package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type MongoOpts struct {
	ConnectionTimeout time.Duration
	MaxPoolSize       uint64
}

func NewMongoOpts() MongoOpts {
	return MongoOpts{
		ConnectionTimeout: time.Second * 5,
		MaxPoolSize:       100,
	}
}

type Mongo struct {
	dbClient *mongo.Client
	db       *mongo.Database
	opts     MongoOpts
}

func NewMongo(dbUri string, dbName string, opts MongoOpts) (*Mongo, error) {
	clientOpts := options.Client().ApplyURI(dbUri).SetMaxPoolSize(opts.MaxPoolSize)
	ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectionTimeout)
	defer cancel()
	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	return &Mongo{
		db:       client.Database(dbName),
		dbClient: client,
		opts:     opts,
	}, nil
}

func (m *Mongo) Ping(ctx context.Context) error {
	return m.dbClient.Ping(ctx, readpref.Primary())
}

func (m *Mongo) Close(ctx context.Context) error {
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	return m.dbClient.Disconnect(_ctx)
}

func (m *Mongo) FindColl(ctx context.Context, collName string) (bool, error) {
	nameOnly := true
	opts := options.ListCollectionsOptions{
		NameOnly: &nameOnly,
	}
	var exists bool = false
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	if names, err := m.db.ListCollectionNames(_ctx, bson.D{}, &opts); err != nil {
		return false, err
	} else {
		for _, name := range names {
			if name == collName {
				exists = true
				break
			}
		}
	}
	return exists, nil
}

func (m *Mongo) CreateTimeSeriesColl(ctx context.Context, collName string, opts db.TimeSeriesOpts) error {
	eas := opts.ExpireAfter
	_opts := options.CreateCollectionOptions{
		TimeSeriesOptions: &options.TimeSeriesOptions{
			TimeField: opts.TimeField,
			MetaField: &opts.MetaField,
		},
		ExpireAfterSeconds: &eas,
	}
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	err := m.db.CreateCollection(_ctx, collName, &_opts)
	if err == nil {
		return nil
	}
	// check if the error is caused by existing collection
	if exists, findErr := m.FindColl(_ctx, collName); findErr != nil {
		return errors.Join(findErr, db.ErrCollectionCheckFailed)
	} else if !exists {
		return errors.Join(findErr, db.ErrCollectionCreateFailed)
	} else {
		return db.ErrCollectionAlreadyExists
	}
}

func (m *Mongo) Insert(ctx context.Context, collName string, objs []any) error {
	coll := m.getCurColl(collName)
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	opts := options.InsertMany().SetOrdered(false)
	if _, err := coll.InsertMany(_ctx, objs, opts); err != nil {
		return err
	}
	return nil
}

func (m *Mongo) getCurColl(collName string) *mongo.Collection {
	return m.db.Collection(collName)
}
