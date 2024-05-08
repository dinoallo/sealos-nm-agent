package mongo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/common"
	errutil "github.com/dinoallo/sealos-networkmanager-agent/pkg/errors/util"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	ErrSelectorConvertFailed = errors.New("unable to convert the selector to a string. maybe this selector is invalid")
)

type MongoOpts struct {
	DBURI             string
	DBName            string
	ConnectionTimeout time.Duration
	MaxPoolSize       uint64
	// a specific ip used for the outgoing connection to mongo. This needs to be set alongside SrcPort
	SrcIP string
	// a specific port used for the outgoing connection to mongo. If it's zero, choose a random one.
	SrcPort uint32
	Logger  log.Logger
}

type Mongo struct {
	logger   log.Logger
	dbClient *mongo.Client
	db       *mongo.Database
	opts     MongoOpts
}

func NewMongo(opts MongoOpts) (*Mongo, error) {
	clientOpts := options.Client().ApplyURI(opts.DBURI).SetMaxPoolSize(opts.MaxPoolSize)
	if opts.SrcPort != 0 {
		//TODO: currently only tcp connection is supported
		mongoClientAddr := fmt.Sprintf("%v:%v", opts.SrcIP, opts.SrcPort)
		localAddr, err := net.ResolveTCPAddr("tcp", mongoClientAddr)
		if err != nil {
			return nil, err
		}
		d := net.Dialer{
			LocalAddr: localAddr,
		}
		clientOpts.SetDialer(&d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectionTimeout)
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

func (m *Mongo) CreateTimeSeriesColl(ctx context.Context, collName string, opts common.TimeSeriesOpts) error {
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
		return errutil.Err(common.ErrCollectionCheckFailed, findErr)
	} else if !exists {
		return errutil.Err(common.ErrCollectionCreateFailed, err)
	} else {
		return common.ErrCollectionAlreadyExists
	}
}
func (m *Mongo) FindPartialTTLIndex(ctx context.Context, collName string, opts common.PartialTTLIndexOpts) (bool, error) {
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
		if _name, ok := result["name"]; ok && _name == opts.PartialTTLIndexName {
			exists = true
			break
		}
	}
	return exists, nil
}
func (m *Mongo) CreatePartialTTLIndex(ctx context.Context, collName string, opts common.PartialTTLIndexOpts) error {
	if opts.IndexKeys == nil || opts.PartialFilterExpression == nil {
		return common.ErrArgumentInvalid
	}
	coll := m.getCurColl(collName)
	idKeys, err := ToBSONFilter(opts.IndexKeys)
	if err != nil {
		return err
	}
	pfe, err := ToBSONFilter(opts.PartialFilterExpression)
	if err != nil {
		return err
	}
	mongoOpts := options.IndexOptions{
		Name:                    &opts.PartialTTLIndexName,
		ExpireAfterSeconds:      &opts.ExpireAfter,
		PartialFilterExpression: pfe,
	}
	indexModel := mongo.IndexModel{
		Keys:    idKeys,
		Options: &mongoOpts,
	}
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	_, err = coll.Indexes().CreateOne(_ctx, indexModel)
	if err == nil {
		return nil
	}
	if exists, findErr := m.FindPartialTTLIndex(_ctx, collName, opts); findErr != nil {
		return errutil.Err(common.ErrPartialTTLIndexCheckFailed, findErr)
	} else if !exists {
		return errutil.Err(common.ErrPartialTTLIndexCreateFailed, err)
	} else {
		return common.ErrPartialTTLIndexAlreadyExists
	}
}

func (m *Mongo) GetOne(ctx context.Context, collName string, selector common.Selector, obj any) (bool, error) {
	coll := m.getCurColl(collName)
	filter, err := ToBSONFilter(&selector)
	if err != nil {
		return false, err
	}
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

func (m *Mongo) rawGetOne(ctx context.Context, collName string, filter any, obj any) (bool, error) {
	coll := m.getCurColl(collName)
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	if err := coll.FindOne(_ctx, filter).Decode(obj); err == nil {
		return true, nil
	} else if err == mongo.ErrNoDocuments {
		return false, nil
	} else {
		return false, err
	}
}

func (m *Mongo) Get(ctx context.Context, collName string, selector common.Selector, objs any, opts common.GetOpts) error {
	var mongoOpts *options.FindOptions
	if opts.Size > 0 {
		mongoOpts = options.Find().SetLimit(int64(opts.Size))
	}
	filter, err := ToBSONFilter(&selector)
	if err != nil {
		return err
	}
	coll := m.getCurColl(collName)
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	cursor, err := coll.Find(_ctx, filter, mongoOpts)
	if err != nil {
		return err
	}
	if err = cursor.All(_ctx, objs); err != nil {
		return err
	}
	return nil
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

func (m *Mongo) ReplaceOne(ctx context.Context, collName string, selector common.Selector, replacement any) error {
	coll := m.getCurColl(collName)
	_ctx, cancel := context.WithTimeout(ctx, m.opts.ConnectionTimeout)
	defer cancel()
	opts := options.Replace().SetUpsert(true)
	filter, err := ToBSONFilter(&selector)
	if err != nil {
		return err
	}
	if _, err := coll.ReplaceOne(_ctx, *filter, replacement, opts); err != nil {
		return err
	}
	return nil
}

func (m *Mongo) getCurColl(collName string) *mongo.Collection {
	return m.db.Collection(collName)
}
