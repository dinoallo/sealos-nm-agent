package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	// "github.com/puzpuzpuz/xsync"
	"go.uber.org/zap"

	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"

	"golang.org/x/sync/errgroup"
)

const (
	TRAFFIC_MONITOR_WORKER_COUNT            = (1 << 4)
	TRAFFIC_MONITOR_MANAGER_COUNT           = (1 << 3)
	TRAFFIC_MONITOR_SYNC_TIME               = time.Second * 30
	TRAFFIC_MONITOR_SYNC_MAX_ENTRIES_SIZE   = (1 << 20)
	TRAFFIC_RECORD_MAX_BUFFER_SIZE          = (1 << 10)
	TRAFFIC_RECORD_DEFAULT_COUNTER_DEADLINE = time.Minute
)

type TrafficMonitorStore struct {
	name   string
	logger *zap.SugaredLogger
	p      *persistent

	trafficMonitors    map[string]*TrafficMonitor
	tmMu               sync.RWMutex
	trafficRecords     chan *TrafficRecord
	trafficMonitorSync *lru_expirable.LRU[string, *TrafficMonitor]
}

func NewTrafficMonitorStore(baseLogger *zap.SugaredLogger, p *persistent) (*TrafficMonitorStore, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	trafficRecords := make(chan *TrafficRecord)
	trafficMonitors := make(map[string]*TrafficMonitor)
	name := "traffic_meter_store"
	return &TrafficMonitorStore{
		name:            name,
		p:               p,
		logger:          baseLogger.With(zap.String("component", name)),
		trafficRecords:  trafficRecords,
		trafficMonitors: trafficMonitors,
		tmMu:            sync.RWMutex{},
	}, nil
}

func (s *TrafficMonitorStore) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	s.trafficMonitorSync = lru_expirable.NewLRU[string, *TrafficMonitor](TRAFFIC_MONITOR_SYNC_MAX_ENTRIES_SIZE, s.onEvicted, TRAFFIC_MONITOR_SYNC_TIME)
	p := s.p
	if found, err := p.findCollection(ctx, TRCollection); err != nil {
		return err
	} else if !found {
		mf := TRAFFIC_RECORD_META_FIELD
		if err := p.createTSDB(ctx, TRCollection, TRAFFIC_RECORD_TIME_FIELD, &mf); err != nil {
			if err != util.ErrCollectionAlreadyExists {
				return err
			}
		}
	}
	managerEg := errgroup.Group{}
	managerEg.SetLimit(TRAFFIC_MONITOR_MANAGER_COUNT)
	workerEg := errgroup.Group{}
	workerEg.SetLimit(TRAFFIC_MONITOR_WORKER_COUNT)
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

func (s *TrafficMonitorStore) GetName() string {
	return s.name
}

func (s *TrafficMonitorStore) Stop(ctx context.Context) error {
	return nil
}

func (s *TrafficMonitorStore) AddSentBytes(ctx context.Context, report *TrafficReport) error {
	// key := fmt.Sprintf("%v/%v/%v", report.TrafficReportMeta.SrcIP, report.TrafficReportMeta.SrcPort, report.Dir)
	ip := report.TrafficReportMeta.SrcIP
	// ensure m exists
	s.tmMu.RLock()
	if m, exists := s.trafficMonitors[ip]; !exists {
		s.tmMu.RUnlock()
		s.tmMu.Lock()
		m = &TrafficMonitor{
			IP:      ip,
			Metrics: make(map[uint32]*TrafficMonitorMetrics),
			mu:      sync.RWMutex{},
		}
		s.trafficMonitors[ip] = m
		s.tmMu.Unlock()
	} else {
		s.tmMu.RUnlock()
	}
	s.tmMu.RLock()
	defer s.tmMu.RUnlock()
	m, exists := s.trafficMonitors[ip]
	if !exists {
		return nil
	}
	if _, ok := s.trafficMonitorSync.Get(ip); !ok {
		s.trafficMonitorSync.Add(ip, m)
	}

	port := report.TrafficReportMeta.SrcPort
	// ensure met actually exists
	m.mu.RLock()
	if met, exists := m.Metrics[port]; exists {
		met.SentBytes.Add(report.DataBytes)
		m.mu.RUnlock()
		return nil
	} else {
		m.mu.RUnlock()
		m.mu.Lock()
		met = &TrafficMonitorMetrics{
			SentBytes: atomic.Uint32{},
			RecvBytes: atomic.Uint32{},
		}
		m.Metrics[port] = met
		m.mu.Unlock()
	}

	m.mu.RLock()
	if met, exists := m.Metrics[port]; exists {
		met.SentBytes.Add(report.DataBytes)
	}
	m.mu.RUnlock()
	return nil
}

func (s *TrafficMonitorStore) startManager(ctx context.Context, workerEg *errgroup.Group) error {
	buf := &[]interface{}{}
	curBuf := buf
	curCounter := NewDeadlineCounter(TRAFFIC_RECORD_MAX_BUFFER_SIZE, TRAFFIC_RECORD_DEFAULT_COUNTER_DEADLINE)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			select {
			case <-curCounter.C:
				s.logger.Infof("counter is done; start flushing")
				s.startWorker(curBuf, workerEg)
				buf = &[]interface{}{}
				curBuf = buf
				curCounter = NewDeadlineCounter(TRAFFIC_RECORD_MAX_BUFFER_SIZE, TRAFFIC_RECORD_DEFAULT_COUNTER_DEADLINE)
			default:
				if t, err := s.get(); err == nil {
					*curBuf = append(*curBuf, t)
					curCounter.Add(1)
				} else if err == util.ErrTimeoutWaitingForTrafficMonitor {
					s.startWorker(curBuf, workerEg)
					buf = &[]interface{}{}
					curBuf = buf
					curCounter.Stop()
					curCounter = NewDeadlineCounter(TRAFFIC_RECORD_MAX_BUFFER_SIZE, TRAFFIC_RECORD_DEFAULT_COUNTER_DEADLINE)
				} else {
					return err
				}
			}

		}
	}
}

func (s *TrafficMonitorStore) startWorker(curBuf *[]interface{}, eg *errgroup.Group) {
	buf := curBuf
	if ifWorkerStarted := eg.TryGo(func() error {
		return s.flush(buf)
	}); !ifWorkerStarted {
		s.logger.Errorf("unable to flush traffic since we cannot create more workers")
	}
}

func (s *TrafficMonitorStore) flush(buf *[]interface{}) error {
	logger := s.logger
	ps := s.p
	if ps != nil {
		if len(*buf) > 0 {
			insertCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			if err := ps.insertMany(insertCtx, TRCollection, *buf); err != nil {
				logger.Errorf("unable to flush to the database: %v", err)
				return err
			}
			logger.Infof("%v traffic meters were flushed", len(*buf))
		}
	} else {
		return util.ErrPersistentStorageNotInited
	}
	return nil
}

func (s *TrafficMonitorStore) get() (*TrafficRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, util.ErrTimeoutWaitingForTrafficMonitor
	case t := <-s.trafficRecords:
		return t, nil
	}
}

func (s *TrafficMonitorStore) onEvicted(key string, monitor *TrafficMonitor) {
	if monitor == nil {
		return
	}
	ip := monitor.IP
	monitor.mu.RLock()
	for port, m := range monitor.Metrics {
		if m == nil {
			continue
		}
		dataBytes := m.SentBytes.Swap(0)
		if dataBytes == 0 {
			continue
		}
		dir := TRAFFIC_DIR_V4_EGRESS
		tr_id := fmt.Sprintf("%v/%v/%v", ip, port, dir)
		t := TrafficRecord{
			TrafficRecordMeta: TrafficRecordMetaData{
				Port: port,
				Dir:  dir,
				IP:   ip,
			},
			DataBytes: dataBytes,
			ID:        tr_id,
			Timestamp: time.Now(),
		}
		s.trafficRecords <- &t
	}
	monitor.mu.RUnlock()
}
