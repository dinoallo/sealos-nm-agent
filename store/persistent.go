package store

import (
	"context"
	"fmt"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/sync/errgroup"
)

const (
	DB_CONNECTION_TIMEOUT = time.Second * 10
	MAX_POOL_SIZE         = 100

	DEFAULT_EXPIRE_AFTER_SECONDS = 1800
)

type DBCred struct {
	DBURI string
	DB    string
}

type persistent struct {
	name     string
	dbClient *mongo.Client
	database *mongo.Database
	cred     DBCred
}

func NewPersistent(cred DBCred) *persistent {
	name := "persistent_store"
	return &persistent{
		name:     name,
		dbClient: nil,
		database: nil,
		cred:     cred,
	}
}

func (p *persistent) GetName() string {
	return p.name
}

func (p *persistent) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	if err := p.connect(ctx); err != nil {
		return err
	}
	mainEg.Go(func() error {
		return nil
	})
	return nil
}

func (p *persistent) Stop(ctx context.Context) error {
	return p.disconnect(ctx)
}

func (p *persistent) connect(ctx context.Context) error {
	// initialize the database
	cred := p.cred
	clientOps := options.Client().ApplyURI(cred.DBURI).SetMaxPoolSize(MAX_POOL_SIZE)
	connectCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
	defer cancel()
	if client, err := mongo.Connect(connectCtx, clientOps); err != nil {
		return err
	} else {
		p.dbClient = client
	}
	//TODO: ping before doing any operations
	if err := p.dbClient.Ping(connectCtx, readpref.Primary()); err != nil {
		return err
	} else {
		p.database = p.dbClient.Database(cred.DB)
	}
	return nil
}

func (p *persistent) disconnect(ctx context.Context) error {
	if p.dbClient == nil {
		return util.ErrPersistentStorageNotInited
	}
	disconnectCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
	defer cancel()
	return p.dbClient.Disconnect(disconnectCtx)
}

func (p *persistent) findOne(ctx context.Context, collMeta Coll, k string, v string, obj interface{}) (bool, error) {
	getCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
	defer cancel()
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return false, err
	} else {
		filter := bson.D{
			{
				Key:   k,
				Value: v,
			},
		}
		if err := coll.FindOne(getCtx, filter).Decode(obj); err != nil {
			if err != mongo.ErrNoDocuments {
				return false, err
			} else {
				return false, nil
			}
		}
		return true, nil
	}
}

func (p *persistent) findAll(ctx context.Context, collMeta Coll, size int64, objs interface{}) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		var opts *options.FindOptions
		if size > 0 {
			opts = options.Find().SetLimit(size)
		}
		findCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		if cursor, err := coll.Find(findCtx, bson.D{}, opts); err != nil {
			return err
		} else {
			if err = cursor.All(ctx, objs); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *persistent) deleteOne(ctx context.Context, collMeta Coll, k string, v string) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		delCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		filter := bson.D{{
			Key:   k,
			Value: v,
		}}
		if _, err := coll.DeleteOne(delCtx, filter); err != nil {
			return err
		}
	}
	return nil
}

func (p *persistent) deleteMany(ctx context.Context, collMeta Coll, items []interface{}) error {
	if collMeta == CEPCollection {
		var eids []int64
		for _, item := range items {
			if cep, ok := item.(CiliumEndpoint); ok {
				eids = append(eids, cep.EndpointID)
			} else {
				return fmt.Errorf("conversion error; the interface is not a CiliumEndpoint")
			}
		}
		if coll, err := p.getCurrentCollection(collMeta); err != nil {
			return err
		} else {
			deleteCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
			defer cancel()
			opts := options.Delete().SetHint(bson.D{{Key: "endpoint_id", Value: 1}})
			filter := bson.D{
				{
					Key: "endpoint_id",
					Value: bson.D{
						{
							Key:   "$in",
							Value: eids,
						},
					},
				},
			}
			if _, err := coll.DeleteMany(deleteCtx, filter, opts); err != nil {
				return err
			}
		}
	} else {
		// not implemented
		return nil
	}
	return nil
}

func (p *persistent) replaceOne(ctx context.Context, collMeta Coll, k string, v string, replacement interface{}) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		putCtx, cancel := context.WithTimeout(context.TODO(), DB_CONNECTION_TIMEOUT)
		defer cancel()
		opts := options.Replace().SetUpsert(true)
		filter := bson.D{{
			Key:   k,
			Value: v,
		}}
		if _, err := coll.ReplaceOne(putCtx, filter, replacement, opts); err != nil {
			return err
		}
	}
	return nil
}

func (p *persistent) unsetOne(ctx context.Context, collMeta Coll, k string, v string, field string) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		updateCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		filter := bson.D{{
			Key:   k,
			Value: v,
		}}
		update := bson.D{{
			Key: "$unset",
			Value: bson.D{{
				Key:   field,
				Value: 1,
			}},
		}}
		if _, err := coll.UpdateOne(updateCtx, filter, update); err != nil {
			return err
		}
	}
	return nil

}

func (p *persistent) insertOne(ctx context.Context, collMeta Coll, item interface{}) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		insertCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		if _, err := coll.InsertOne(insertCtx, item); err != nil {
			return err
		}
	}
	return nil
}

func (p *persistent) insertMany(ctx context.Context, collMeta Coll, items []interface{}) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		insertCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		opts := options.InsertMany().SetOrdered(false)
		if _, err := coll.InsertMany(insertCtx, items, opts); err != nil {
			return err
		}
	}
	return nil
}

func (p *persistent) findCollection(ctx context.Context, collMeta Coll) (bool, error) {
	if p.database == nil {
		return false, util.ErrPersistentStorageNotInited
	}
	nameOnly := true
	opts := options.ListCollectionsOptions{
		NameOnly: &nameOnly,
	}
	collName := collMeta.Prefix
	var exists bool = false
	if names, err := p.database.ListCollectionNames(ctx, bson.D{}, &opts); err != nil {
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

func (p *persistent) createTSDB(ctx context.Context, collMeta Coll, tf string, mf *string) error {
	if p.database == nil {
		return util.ErrPersistentStorageNotInited
	}
	var eas int64 = DEFAULT_EXPIRE_AFTER_SECONDS
	collName := collMeta.Prefix
	opts := options.CreateCollectionOptions{
		TimeSeriesOptions: &options.TimeSeriesOptions{
			TimeField: tf,
			MetaField: mf,
		},
		ExpireAfterSeconds: &eas,
	}
	createCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
	defer cancel()
	if err := p.database.CreateCollection(createCtx, collName, &opts); err != nil {
		// check if the error is caused by existing collection
		if exists, findErr := p.findCollection(createCtx, TRCollection); findErr != nil {
			return fmt.Errorf("unable to create the collection: %v, and it's also unable check if the colletion exists: %v", err, findErr)
		} else if !exists {
			return err
		} else {
			return util.ErrCollectionAlreadyExists
		}
	}
	return nil
}

func (p *persistent) findPartialTTLIndex(ctx context.Context, collMeta Coll, name string) (bool, error) {
	var exists bool = false
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return false, err
	} else {
		listCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		if cursor, err := coll.Indexes().List(listCtx); err != nil {
			return false, err
		} else {
			var results []bson.M
			if err := cursor.All(listCtx, &results); err != nil {
				return false, err
			} else {
				for _, result := range results {
					if _name, ok := result["name"]; ok && _name == name {
						exists = true
						break
					}
				}
			}
		}
	}
	return exists, nil
}

func (p *persistent) setupCiliumEndpointAutoDeletion(ctx context.Context, collMeta Coll, name string) error {
	if p.database == nil {
		return util.ErrPersistentStorageNotInited
	}
	var eas int32 = DEFAULT_EXPIRE_AFTER_SECONDS
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		key := bson.D{
			{
				Key:   "deleted_time",
				Value: 1,
			},
		}
		pfe := bson.D{
			{
				Key: "deleted_time",
				Value: bson.D{
					{
						Key:   "$gt",
						Value: time.Time{},
					},
				},
			},
		}
		indexName := name
		opts := options.IndexOptions{
			Name:                    &indexName,
			ExpireAfterSeconds:      &eas,
			PartialFilterExpression: pfe,
		}
		indexModel := mongo.IndexModel{
			Keys:    key,
			Options: &opts,
		}
		createIndexCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		if _, err := coll.Indexes().CreateOne(createIndexCtx, indexModel); err != nil {
			if exists, findErr := p.findPartialTTLIndex(createIndexCtx, collMeta, name); findErr != nil {
				return fmt.Errorf("unable to create the partial ttl index: %v, and it's also unable check if the index exists: %v", err, findErr)
			} else if !exists {
				return err
			} else {
				return util.ErrPartialTTLIndexAlreadyExists
			}
		}
	}
	return nil
}

func (p *persistent) getCurrentCollection(collMeta Coll) (*mongo.Collection, error) {
	db := p.database
	if db == nil {
		return nil, fmt.Errorf("the database shouldn't be nil")
	}
	var collName string
	switch collMeta.T {
	case COLL_TYPE_TR:
		collName = fmt.Sprintf("%s", collMeta.Prefix)
	case COLL_TYPE_CEP:
		collName = fmt.Sprintf("%s", collMeta.Prefix)
	}
	coll := db.Collection(collName)
	return coll, nil
}
