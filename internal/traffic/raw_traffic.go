package traffic

import (
	"context"
	"sync"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/cache"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/db"
	errutil "github.com/dinoallo/sealos-networkmanager-library/pkg/errors/util"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/host"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/log"
	"golang.org/x/sync/errgroup"
)

type RawTrafficHandlerConfig struct {
	// DefaultColl is the collection where to flush raw traffic items
	DefaultColl string
	// SummaryColl is the collection where to flush summary raw traffic items
	SummaryColl string
	// MaxWorkerCount is the max number of worke to process raw traffic items
	MaxWorkerCount int
	// BatchSize is the size of the items that a worker process at once
	BatchSize int
	// GetBatchTimeout is the timeout for a worker to get a batch
	GetBatchTimeout time.Duration
	// FlushTimeout is the timeout for a worker to insert a batch of items
	FlushTimeout time.Duration
	// DefaultCacheConfig is the configuration for the default cache
	DefaultCacheConfig cache.CacheConfig
	// SummaryCacheConfig is the configuration for the summary cache
	SummaryCacheConfig cache.CacheConfig
}

func NewRawTrafficHandlerConfig() RawTrafficHandlerConfig {
	return RawTrafficHandlerConfig{
		DefaultColl:        "raw_traffic",
		SummaryColl:        "raw_traffic_summary",
		MaxWorkerCount:     4,
		BatchSize:          100,
		GetBatchTimeout:    10 * time.Second,
		FlushTimeout:       10 * time.Second,
		DefaultCacheConfig: cache.NewCacheConfig(),
		SummaryCacheConfig: cache.NewCacheConfig(),
	}
}

type RawTrafficHandlerParams struct {
	// DB is the module to perform database operations
	DB db.DB
	// ParentLogger is the parent logger used to create a logger
	ParentLogger log.Logger
	RawTrafficHandlerConfig
}

type RawTrafficHandler struct {
	// logger is used to log info, errors, etc
	logger log.Logger
	// defaultCache is the cache to store usual metrics
	defaultCache *cache.Cache[*rawTrafficMetricEntry, structs.RawTraffic]
	// summaryCache is the cache to store regularly summarized metrics
	summaryCache *cache.Cache[*rawTrafficMetricEntry, structs.RawTraffic]
	RawTrafficHandlerParams
}

func NewRawTrafficHandler(params RawTrafficHandlerParams) (*RawTrafficHandler, error) {
	logger, err := params.ParentLogger.WithCompName("raw_traffic_handler")
	if err != nil {
		return nil, errutil.Err(ErrCreatingLogger, err)
	}
	defaultCache, err := cache.NewCache[*rawTrafficMetricEntry, structs.RawTraffic](params.DefaultCacheConfig)
	if err != nil {
		return nil, err
	}
	summaryCache, err := cache.NewCache[*rawTrafficMetricEntry, structs.RawTraffic](params.SummaryCacheConfig)
	if err != nil {
		return nil, err
	}
	return &RawTrafficHandler{
		logger:                  logger,
		defaultCache:            defaultCache,
		summaryCache:            summaryCache,
		RawTrafficHandlerParams: params,
	}, nil
}

func (h *RawTrafficHandler) Start(ctx context.Context) error {
	h.start(ctx, h.defaultCache, h.DefaultColl)
	h.start(ctx, h.summaryCache, h.SummaryColl)
	return nil
}

func (h *RawTrafficHandler) start(ctx context.Context, cache *cache.Cache[*rawTrafficMetricEntry, structs.RawTraffic], coll string) error {
	wg := &errgroup.Group{}
	wg.SetLimit(h.MaxWorkerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					if err := h.handleRawTraffic(ctx, cache, coll); err != nil {
						h.logger.Errorf("%v", err)
						return err
					}
					return nil
				})
			}
		}
	}()
	return nil
}

func (h *RawTrafficHandler) AcceptRawTrafficEvent(ctx context.Context, event structs.RawTrafficEvent) error {
	// accept for the source ip
	srcHash := getHash(event.RawTrafficEventMeta.SrcIP)
	srcTags := event.GetTagsForSrc()
	srcMetricValue := structs.RawTrafficMetric{
		SentBytes: event.DataBytes,
	}
	for _, srcTag := range srcTags {
		if err := h.accept(srcHash, srcTag, srcMetricValue); err != nil {
			return err
		}
	}

	// accept for the dst ip
	dstHash := getHash(event.RawTrafficEventMeta.DstIP)
	dstTags := event.GetTagsForDst()
	dstMetricValue := structs.RawTrafficMetric{
		RecvBytes: event.DataBytes,
	}
	for _, dstTag := range dstTags {
		if err := h.accept(dstHash, dstTag, dstMetricValue); err != nil {
			return err
		}
	}

	return nil
}

func (h *RawTrafficHandler) accept(hash, tag string, metricValue structs.RawTrafficMetric) error {
	if err := h.updateMetric(hash, tag, metricValue, h.defaultCache); err != nil {
		return err
	}
	if err := h.updateMetric(hash, tag, metricValue, h.summaryCache); err != nil {
		return err
	}
	return nil
}

func (h *RawTrafficHandler) handleRawTraffic(ctx context.Context, c *cache.Cache[*rawTrafficMetricEntry, structs.RawTraffic], coll string) error {
	batch, err := c.GetBatchExpiredEntries(ctx, h.GetBatchTimeout, h.BatchSize) //TODO: make this configurable
	if err != nil {
		if err == cache.ErrTimeoutGettingExpiredEntries {
			// h.logger.Info("timeout! flush now!")
		} else {
			return err
		}
	}
	if len(batch) <= 0 {
		return nil
	}
	db := h.DB
	_ctx, cancel := context.WithTimeout(ctx, h.FlushTimeout)
	defer cancel()
	//TODO: optimize this! do we really need copying?
	var items []any
	for _, item := range batch {
		items = append(items, item)
	}
	if err := db.Insert(_ctx, coll, items); err != nil {
		return err
	}
	return nil
}

func (h *RawTrafficHandler) updateMetric(hash, tag string, metricValue structs.RawTrafficMetric, c *cache.Cache[*rawTrafficMetricEntry, structs.RawTraffic]) error {
	node, err := host.GetName()
	if err != nil {
		return err
	}
	newEntry := &rawTrafficMetricEntry{
		hash:    hash,
		metrics: &sync.Map{},
		meta: rawTrafficMetricEntryMeta{
			ip:   getIP(hash),
			node: node,
		},
	}
	entry, err := c.LoadOrStore(hash, newEntry)
	if err != nil {
		return err
	}
	metric, err := entry.Load(tag)
	if err != nil {
		return err
	}
	metric.sentBytes.Add(metricValue.SentBytes)
	metric.recvBytes.Add(metricValue.RecvBytes)
	return nil
}

// TODO: move this three functions to common structs
func getIP(hash string) string {
	//TODO: imple me
	return hash
}

func getHash(ip string) string {
	return ip
}
