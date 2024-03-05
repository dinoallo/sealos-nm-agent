package persistent

import (
	"context"
	"fmt"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (p *Persistent) createTimeSeriesColl(ctx context.Context, collMeta store.Coll, tf string, mf *string) error {
	if p.database == nil {
		return util.ErrPersistentStorageNotInited
	}
	var eas int64 = int64(p.cfg.ExpireAfter)
	collName := collMeta.Name
	opts := options.CreateCollectionOptions{
		TimeSeriesOptions: &options.TimeSeriesOptions{
			TimeField: tf,
			MetaField: mf,
		},
		ExpireAfterSeconds: &eas,
	}
	createCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
	defer cancel()
	if err := p.database.CreateCollection(createCtx, collName, &opts); err != nil {
		// check if the error is caused by existing collection
		coll := collMeta
		if exists, findErr := p.findCollection(createCtx, coll); findErr != nil {
			return fmt.Errorf("unable to create the collection: %v, and it's also unable check if the colletion exists: %v", err, findErr)
		} else if !exists {
			return err
		} else {
			return util.ErrCollectionAlreadyExists
		}
	}
	return nil
}

func (p *Persistent) findCollection(ctx context.Context, collMeta store.Coll) (bool, error) {
	if p.database == nil {
		return false, util.ErrPersistentStorageNotInited
	}
	nameOnly := true
	opts := options.ListCollectionsOptions{
		NameOnly: &nameOnly,
	}
	collName := collMeta.Name
	var exists bool = false
	_ctx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
	defer cancel()
	if names, err := p.database.ListCollectionNames(_ctx, bson.D{}, &opts); err != nil {
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

func (p *Persistent) findPartialTTLIndex(ctx context.Context, collMeta store.Coll, name string) (bool, error) {
	var exists bool = false
	if coll, err := p.getCurrentCollection(collMeta); err != nil {
		return false, err
	} else {
		listCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
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
func (p *Persistent) createPartialTTLIndex(ctx context.Context, collMeta store.Coll, name string) error {
	if p.database == nil {
		return util.ErrPersistentStorageNotInited
	}
	var eas int32 = int32(p.cfg.ExpireAfter)
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
		createIndexCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
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
