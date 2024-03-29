package persistent

import (
	"context"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type Persistent struct {
	name     string
	dbURI    string
	dbClient *mongo.Client
	database *mongo.Database
	cfg      conf.PersistentStorageConfig
	param    PersistentParam
	logger   *zap.SugaredLogger
}

func newPersistent(pp PersistentParam, cfg conf.PersistentStorageConfig) *Persistent {
	name := "persistent"
	logger := pp.ParentLogger.With("component", name)
	return &Persistent{
		name:     name,
		dbClient: nil,
		database: nil,
		cfg:      cfg,
		dbURI:    pp.DBURI,
		param:    pp,
		logger:   logger,
	}
}

func (p *Persistent) connect(ctx context.Context) error {
	// initialize the database
	clientOps := options.Client().ApplyURI(p.dbURI).SetMaxPoolSize(uint64(p.cfg.MaxPoolSize))
	connectCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
	defer cancel()
	if client, err := mongo.Connect(connectCtx, clientOps); err != nil {
		return err
	} else {
		p.dbClient = client
	}
	p.database = p.dbClient.Database(p.cfg.DBName)
	return nil
}

func (p *Persistent) disconnect(ctx context.Context) error {
	if p.dbClient == nil {
		return util.ErrPersistentStorageNotInited
	}
	disconnectCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.ConnectionTimeout)*time.Second)
	defer cancel()
	return p.dbClient.Disconnect(disconnectCtx)
}
