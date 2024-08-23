package db

import (
	"context"
	"errors"
)

var (
	ErrCollectionAlreadyExists = errors.New("this collection already exists")
	ErrCollectionCreateFailed  = errors.New("unable to create the collection")
	ErrCollectionCheckFailed   = errors.New("unable to check if the collection exists")
)

type TimeSeriesOpts struct {
	TimeField   string
	MetaField   string
	ExpireAfter int64
}

type DB interface {
	CreateTimeSeriesColl(ctx context.Context, collName string, opts TimeSeriesOpts) error
	FindColl(ctx context.Context, collName string) (bool, error)
	Insert(ctx context.Context, collName string, objs []any) error
}
