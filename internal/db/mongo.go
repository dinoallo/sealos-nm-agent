package db

import (
	"context"
	"fmt"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type MongoOpts struct {
	DBURI             string
	DBName            string
	ConnectionTimeout time.Duration
	MaxPoolSize       uint64
	ExpireAfter       int64
	Logger            *zap.SugaredLogger
}

type Mongo struct {
	logger   *zap.SugaredLogger
	dbClient *mongo.Client
	db       *mongo.Database
	opts     MongoOpts
}

func NewMongo(opts MongoOpts) (*Mongo, error) {
	clientOpts := options.Client().ApplyURI(opts.DBURI).SetMaxPoolSize(opts.MaxPoolSize)
	ctx, cancel := context.WithTimeout(context.TODO(), opts.ConnectionTimeout)
	defer cancel()
	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	return &Mongo{
		logger:   opts.Logger,
		db:       client.Database(opts.DBName),
		dbClient: client,
		opts:     opts,
	}, nil
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

func (m *Mongo) CreateTimeSeriesColl(ctx context.Context, collName string, opts TimeSeriesOpts) error {
	eas := m.opts.ExpireAfter
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
		return fmt.Errorf("unable to create the collection: %v, and it's also unable check if the colletion exists: %v", err, findErr)
	} else if !exists {
		return err
	} else {
		return util.ErrCollectionAlreadyExists
	}
}
func (m *Mongo) FindPartialTTLIndex(ctx context.Context, collName string, opts PartialTTLIndexOpts) (bool, error) {
	var exists bool = false
	coll := m.getCurColl(collName)
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	cursor, err := coll.Indexes().List(_ctx)
	if err != nil {
		return false, err
	}
	var results []bson.M
	err = cursor.All(_ctx, &results)
	if err != nil {
		return false, err
	}
	for _, result := range results {
		if _name, ok := result["name"]; ok && _name == collName {
			exists = true
			break
		}
	}
	return exists, nil
}
func CreatePartialTTLIndex(ctx context.Context, collName string, opts PartialTTLIndexOpts)
func (m *Mongo) GetOne(ctx context.Context, collName string, selector any, obj any) (bool, error) {
	coll := m.getCurColl(collName)
	s, ok := (selector).(OneSelector)
	if !ok {
		return false, fmt.Errorf("invalid selector!")
	}
	filter := s.ToBSONFilter()
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	if err := coll.FindOne(_ctx, *filter).Decode(obj); err == nil {
		return true, nil
	} else if err == mongo.ErrNoDocuments {
		return false, nil
	} else {
		return false, err
	}
}
func Get(ctx context.Context, collName string, filter any, objs []any)
func Insert(ctx context.Context, collName string, objs []any)
func (m *Mongo) ReplaceOne(ctx context.Context, collName string, selector any, replacement any) error {
	coll := m.getCurColl(collName)
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	opts := options.Replace().SetUpsert(true)
	s, ok := selector.(OneSelector)
	if !ok {
		return fmt.Errorf("invalid selector!")
	}
	filter := s.ToBSONFilter()
	if _, err := coll.ReplaceOne(_ctx, *filter, replacement, opts); err != nil {
		return err
	}
	return nil
}

func (m *Mongo) getCurColl(collName string) *mongo.Collection {
	return m.db.Collection(collName)
}

type OneSelector struct {
	SelectorKey   string
	SelectorValue string
}

func (s *OneSelector) ToBSONFilter() *bson.D {
	return &bson.D{{
		Key:   s.SelectorKey,
		Value: s.SelectorValue,
	}}
}
