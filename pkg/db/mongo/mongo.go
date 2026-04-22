package mongo

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func (m *Mongo) CreateColl(ctx context.Context, collName string, opts db.CreateCollOpts) error {
	_ = opts
	createOpts := options.CreateCollectionOptions{}
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	err := m.db.CreateCollection(_ctx, collName, &createOpts)
	if err == nil {
		return nil
	}
	// check if the error is caused by existing collection
	if exists, findErr := m.FindColl(_ctx, collName); findErr != nil {
		return errors.Join(findErr, db.ErrCollectionCheckFailed)
	} else if !exists {
		return errors.Join(err, db.ErrCollectionCreateFailed)
	} else {
		return db.ErrCollectionAlreadyExists
	}
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
		return errors.Join(err, db.ErrCollectionCreateFailed)
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

func (m *Mongo) DeleteExpiredBefore(ctx context.Context, collName string, timeField string, expireBefore time.Time) (int64, error) {
	coll := m.getCurColl(collName)
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	filter := bson.M{
		timeField: bson.M{
			"$lt": expireBefore,
		},
	}
	res, err := coll.DeleteMany(_ctx, filter)
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

func (m *Mongo) SupportsTimeSeries(ctx context.Context) (bool, error) {
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()

	collName := fmt.Sprintf("__nm_ts_probe__%d", time.Now().UnixNano())
	timeSeriesOpts := options.CreateCollectionOptions{
		TimeSeriesOptions: &options.TimeSeriesOptions{
			TimeField: "timestamp",
		},
	}

	err := m.db.CreateCollection(_ctx, collName, &timeSeriesOpts)
	if err != nil {
		if isTimeSeriesUnsupportedErr(err) {
			return false, nil
		}
		if isUnauthorizedErr(err) {
			return false, fmt.Errorf("unable to probe time series support because the current MongoDB user is not allowed to create collections: %w", err)
		}
		return false, fmt.Errorf("unable to probe time series support by creating a temporary collection %q: %w", collName, err)
	}

	if dropErr := m.db.Collection(collName).Drop(_ctx); dropErr != nil {
		return true, fmt.Errorf("time series support probe succeeded but failed to drop temporary collection %q: %w", collName, dropErr)
	}

	return true, nil
}

func isTimeSeriesUnsupportedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeseries") &&
		(strings.Contains(msg, "not supported") ||
			strings.Contains(msg, "unknown field") ||
			strings.Contains(msg, "unrecognized field") ||
			strings.Contains(msg, "failed to parse"))
}

func isUnauthorizedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not authorized") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "permission denied")
}

func (m *Mongo) getCurColl(collName string) *mongo.Collection {
	return m.db.Collection(collName)
}
