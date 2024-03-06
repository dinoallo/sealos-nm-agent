package persistent

import (
	"context"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (p *Persistent) getCurrentCollection(collMeta store.Coll) (*mongo.Collection, error) {
	if p.database == nil {
		return nil, nil
	}
	return p.database.Collection(collMeta.Name), nil
}

func (p *Persistent) findAll(ctx context.Context, collMeta store.Coll, size int64, objs interface{}) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		var opts *options.FindOptions
		if size > 0 {
			opts = options.Find().SetLimit(size)
		}
		findCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
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

func (p *Persistent) findOne(ctx context.Context, collMeta store.Coll, filterKey string, filterValue any, obj any) (bool, error) {
	coll, err := p.getCurrentCollection(collMeta)
	if err != nil {
		return false, err
	}
	_ctx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
	defer cancel()
	filter := bson.D{{
		Key:   filterKey,
		Value: filterValue,
	}}
	if err := coll.FindOne(_ctx, filter).Decode(obj); err == nil {
		return true, nil
	} else if err == mongo.ErrNoDocuments {
		return false, nil
	} else {
		return false, err
	}
}

func (p *Persistent) replaceOne(ctx context.Context, collMeta store.Coll, k string, v string, replacement interface{}) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		putCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
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

func (p *Persistent) insertMany(ctx context.Context, collMeta store.Coll, items []interface{}) error {
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return err
	} else {
		insertCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
		defer cancel()
		opts := options.InsertMany().SetOrdered(false)
		if _, err := coll.InsertMany(insertCtx, items, opts); err != nil {
			return err
		}
	}
	return nil
}
