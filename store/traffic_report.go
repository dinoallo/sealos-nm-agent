package store

import (
	"context"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"
	nanoid "github.com/matoous/go-nanoid/v2"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	TRAFFIC_REPORT_MAX_BUFFER_SIZE = (1 << 20)
	TRAFFIC_REPORT_WORKER_COUNT    = (1 << 5)
	TRAFFIC_REPORT_MANAGER_COUNT   = (1 << 3)
	DEFAULT_COUNTER_DEADLINE       = time.Minute
)

type TrafficReportStore struct {
	name           string
	logger         *zap.SugaredLogger
	p              *persistent
	trafficReports chan *TrafficReport
	cache          *lru_expirable.LRU[string, *TrafficReport]
}

func NewTrafficReportStore(baseLogger *zap.SugaredLogger, p *persistent) (*TrafficReportStore, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	trafficReports := make(chan *TrafficReport)
	name := "traffic_report_store"
	return &TrafficReportStore{
		name:           name,
		p:              p,
		logger:         baseLogger.With(zap.String("component", name)),
		trafficReports: trafficReports,
	}, nil
}

func (s *TrafficReportStore) GetName() string {
	return s.name
}

func (s *TrafficReportStore) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	s.cache = lru_expirable.NewLRU[string, *TrafficReport](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_EXPIRED_TIME)
	p := s.p
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	if found, err := p.findCollection(ctx, TRCollection); err != nil {
		return err
	} else if !found {
		metaField := TRAFFIC_REPORT_META_FIELD
		if err := p.createTSDB(ctx, TRCollection, TRAFFIC_REPORT_TIME_FIELD, &metaField); err != nil {
			if err != util.ErrCollectionAlreadyExists {
				return err
			}
		}
	}
	managerEg := errgroup.Group{}
	managerEg.SetLimit(TRAFFIC_REPORT_MANAGER_COUNT)
	workerEg := errgroup.Group{}
	workerEg.SetLimit(TRAFFIC_REPORT_WORKER_COUNT)
	mainEg.Go(
		func() error {
			for {
				managerEg.Go(func() error {
					return s.startManager(ctx, &workerEg)
				})
			}
		})
	return nil
}

func (s *TrafficReportStore) Stop(ctx context.Context) error {
	return nil
}

func (s *TrafficReportStore) startManager(ctx context.Context, workerEg *errgroup.Group) error {
	trafficReportBuffer := &[]interface{}{}
	curTrafficReportBuffer := trafficReportBuffer
	curCounter := NewDeadlineCounter(TRAFFIC_REPORT_MAX_BUFFER_SIZE, DEFAULT_COUNTER_DEADLINE)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			select {
			case <-curCounter.C:
				s.logger.Infof("counter is done; start flushing")
				s.startWorker(curTrafficReportBuffer, workerEg)
				trafficReportBuffer = &[]interface{}{}
				curTrafficReportBuffer = trafficReportBuffer
				curCounter = NewDeadlineCounter(TRAFFIC_REPORT_MAX_BUFFER_SIZE, DEFAULT_COUNTER_DEADLINE)
			default:
				if tr, err := s.getTrafficReport(); err == nil {
					*curTrafficReportBuffer = append(*curTrafficReportBuffer, tr)
					curCounter.Add(1)
				} else if err == util.ErrTimeoutWaitingForTrafficReport {
					s.startWorker(curTrafficReportBuffer, workerEg)
					trafficReportBuffer = &[]interface{}{}
					curTrafficReportBuffer = trafficReportBuffer
					curCounter.Stop()
					curCounter = NewDeadlineCounter(TRAFFIC_REPORT_MAX_BUFFER_SIZE, DEFAULT_COUNTER_DEADLINE)
				} else {
					return err
				}
			}
		}
	}
}

func (s *TrafficReportStore) startWorker(curTrafficReportBuffer *[]interface{}, eg *errgroup.Group) {
	trafficReportBuffer := curTrafficReportBuffer
	if ifWorkerStarted := eg.TryGo(func() error {
		return s.flushTrafficReport(trafficReportBuffer)
	}); !ifWorkerStarted {
		s.logger.Errorf("unable to flush traffic reports since we cannot create more workers")
	}
}

func (s *TrafficReportStore) AddTrafficReport(ctx context.Context, report *TrafficReport) error {
	if report == nil {
		return util.ErrTrafficReportNotInited
	}
	if s.cache == nil {
		return util.ErrCacheNotInited
	}
	if id, err := nanoid.New(16); err != nil {
		return err
	} else {
		s.cache.Add(id, report)
	}
	return nil
}

func (s *TrafficReportStore) flushTrafficReport(trafficReports *[]interface{}) error {
	if s.logger == nil {
		return util.ErrLoggerNotInited
	}
	if trafficReports == nil {
		return nil
	}
	logger := s.logger
	ps := s.p
	if ps != nil {
		if len(*trafficReports) > 0 {
			insertCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()
			if err := ps.insertMany(insertCtx, TRCollection, *trafficReports); err != nil {
				logger.Errorf("unable to flush traffic reports to the database: %v", err)
				return err
			}
			logger.Infof("%v traffic reports were flushed", len(*trafficReports))
		}
	} else {
		return util.ErrPersistentStorageNotInited
	}
	return nil
}

func (s *TrafficReportStore) getTrafficReport() (*TrafficReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, util.ErrTimeoutWaitingForTrafficReport
	case tr := <-s.trafficReports:
		return tr, nil
	}
}

func (s *TrafficReportStore) initCache(ctx context.Context) error {
	p := s.p
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	cache := lru_expirable.NewLRU[string, *TrafficReport](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_EXPIRED_TIME)
	s.cache = cache
	return nil
}

func (s *TrafficReportStore) onEvicted(key string, value *TrafficReport) {
	s.trafficReports <- value
}
