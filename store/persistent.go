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
)

const (
	DB_CONNECTION_TIMEOUT = time.Second * 5
	MAX_POOL_SIZE         = 100
)

type DBCred struct {
	DBURI string
	DB    string
}

type persistent struct {
	dbClient *mongo.Client
	database *mongo.Database
	cred     DBCred
}

func newPersistent(cred DBCred) *persistent {
	return &persistent{
		dbClient: nil,
		database: nil,
		cred:     cred,
	}
}

func (p *persistent) connect(ctx context.Context) error {
	// initialize the database
	cred := p.cred
	clientOps := options.Client().ApplyURI(cred.DBURI).SetMaxPoolSize(MAX_POOL_SIZE)
	if client, err := mongo.Connect(ctx, clientOps); err != nil {
		return err
	} else {
		p.dbClient = client
	}
	//TODO: ping before doing any operations
	if err := p.dbClient.Ping(ctx, readpref.Primary()); err != nil {
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
		opts := options.Find().SetLimit(size)
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

func (p *persistent) getCurrentCollection(collMeta Coll) (*mongo.Collection, error) {
	db := p.database
	if db == nil {
		return nil, fmt.Errorf("the database shouldn't be nil")
	}
	now := time.Now()
	timeSuffix := fmt.Sprintf("%s%s%s", fmt.Sprint(now.Year()), fmt.Sprint(int(now.Month())), fmt.Sprint(now.Day()))
	collName := fmt.Sprintf("%s_%s", collMeta.Prefix, timeSuffix)
	coll := db.Collection(collName)
	return coll, nil
}
