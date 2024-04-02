package db

import "context"

type DB interface {
	FindColl(ctx context.Context, collName string)
	CreateTimeSeriesColl(ctx context.Context, collName string, opts TimeSeriesOpts)
	FindPartialTTLIndex(ctx context.Context, collName string, opts PartialTTLIndexOpts)
	CreatePartialTTLIndex(ctx context.Context, collName string, opts PartialTTLIndexOpts)
	GetOne(ctx context.Context, collName string, selector any, obj any)
	Get(ctx context.Context, collName string, filter any, objs []any)
	Insert(ctx context.Context, collName string, objs []any)
	ReplaceOne(ctx context.Context, collName string, selector any)
}

type TimeSeriesOpts struct {
	TimeField string
	MetaField string
}

type PartialTTLIndexOpts struct {
	PartialTTLIndexName string
}
