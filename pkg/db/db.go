package db

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/common"
)

type DB interface {
	//	CreatePartialTTLIndex(ctx context.Context, collName string, opts common.PartialTTLIndexOpts) error
	CreateTimeSeriesColl(ctx context.Context, collName string, opts common.TimeSeriesOpts) error
	FindColl(ctx context.Context, collName string) (bool, error)
	// FindPartialTTLIndex(ctx context.Context, collName string, opts common.PartialTTLIndexOpts) (bool, error)
	Get(ctx context.Context, collName string, selector common.Selector, objs any, opts common.GetOpts) error
	GetOne(ctx context.Context, collName string, selector common.Selector, obj any) (bool, error)
	Insert(ctx context.Context, collName string, objs []any) error
	ReplaceOne(ctx context.Context, collName string, selector common.Selector) error
}
