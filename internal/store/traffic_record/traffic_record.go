package traffic_record

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	TRAFFIC_RECORD_TIME_FIELD = "timestamp"
	TRAFFIC_RECORD_META_FIELD = "traffic_record_meta"
)

type TrafficMonitorMetrics struct {
	SentBytes atomic.Uint32
	RecvBytes atomic.Uint32
}

type TrafficMonitor struct {
	IP           string
	PortMetrics  map[uint32]*TrafficMonitorMetrics // ordered by port number
	WorldMetrics *TrafficMonitorMetrics
	wmMu         sync.RWMutex
	pmMu         sync.RWMutex
}
type TrafficRecordStore struct {
	name   string
	logger *zap.SugaredLogger

	trafficMonitors    map[string]*TrafficMonitor
	tmMu               sync.RWMutex
	trafficRecordQueue chan *structs.TrafficRecord
	trafficMonitorSync *lru_expirable.LRU[string, *TrafficMonitor]
	trafficReportQueue chan *structs.TrafficReport

	param  TrafficRecordStoreParam
	cfg    conf.TrafficRecordStoreConfig
	p      *persistent.PersistentInterface
	trColl store.Coll
}

func newTrafficRecordStore(param TrafficRecordStoreParam, cfg conf.TrafficRecordStoreConfig) *TrafficRecordStore {
	trafficMonitors := make(map[string]*TrafficMonitor)
	trafficRecordQueue := make(chan *structs.TrafficRecord, cfg.MaxRecordQueueLen)
	trafficReportQueue := make(chan *structs.TrafficReport, cfg.MaxReportQueueLen)
	name := "traffic_record_store"
	logger := param.ParentLogger.With("component", name)
	trColl := store.Coll{
		T:    store.COLL_TYPE_TR,
		Name: cfg.TrafficRecordColl,
	}
	return &TrafficRecordStore{
		name:               name,
		logger:             logger,
		trafficRecordQueue: trafficRecordQueue,
		trafficMonitors:    trafficMonitors,
		trafficReportQueue: trafficReportQueue,
		tmMu:               sync.RWMutex{},
		param:              param,
		cfg:                cfg,
		p:                  param.P,
		trColl:             trColl,
	}
}

func (s *TrafficRecordStore) addTrafficReport(ctx context.Context, report *structs.TrafficReport) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil
	case s.trafficReportQueue <- report:
		return nil
	}
}

func (s *TrafficRecordStore) addSentBytes(ctx context.Context, report *structs.TrafficReport) error {
	// key := fmt.Sprintf("%v/%v/%v", report.TrafficReportMeta.SrcIP, report.TrafficReportMeta.SrcPort, report.Dir)
	ip := report.TrafficReportMeta.SrcIP
	// ensure m exists
	s.tmMu.RLock()
	if m, exists := s.trafficMonitors[ip]; !exists {
		s.tmMu.RUnlock()
		s.tmMu.Lock()
		m = &TrafficMonitor{
			IP:           ip,
			PortMetrics:  make(map[uint32]*TrafficMonitorMetrics),
			WorldMetrics: &TrafficMonitorMetrics{},
			pmMu:         sync.RWMutex{},
			wmMu:         sync.RWMutex{},
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

	if report.Identity == identity.ReservedIdentityWorld {
		m.wmMu.RLock()
		if m.WorldMetrics != nil {
			m.WorldMetrics.SentBytes.Add(report.DataBytes)
		}
		m.wmMu.RUnlock()
	}

	port := report.TrafficReportMeta.SrcPort
	// ensure met actually exists
	m.pmMu.RLock()
	if met, exists := m.PortMetrics[port]; exists {
		met.SentBytes.Add(report.DataBytes)
		m.pmMu.RUnlock()
		return nil
	} else {
		m.pmMu.RUnlock()
		m.pmMu.Lock()
		met = &TrafficMonitorMetrics{
			SentBytes: atomic.Uint32{},
			RecvBytes: atomic.Uint32{},
		}
		m.PortMetrics[port] = met
		m.pmMu.Unlock()
	}

	m.pmMu.RLock()
	if met, exists := m.PortMetrics[port]; exists {
		met.SentBytes.Add(report.DataBytes)
	}
	m.pmMu.RUnlock()
	return nil
}

func (s *TrafficRecordStore) flush(ctx context.Context) error {
	buf := []any{}
	for i := 0; i < s.cfg.MaxRecordToFlush; i++ {
		item := s.get()
		if item == nil {
			break
		}
		buf = append(buf, item)
	}
	if err := s._flush(ctx, &buf); err != nil {
		s.logger.Errorf("unable to flush to the database: %v", err)
		return err
	}
	return nil
}

func (s *TrafficRecordStore) get() *structs.TrafficRecord {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil
	case item := <-s.trafficRecordQueue:
		return item
	}
}

func (s *TrafficRecordStore) _flush(ctx context.Context, buf *[]any) error {
	bufLen := len(*buf)
	if bufLen < 1 {
		return nil
	}
	p := s.p
	if err := p.InsertMany(ctx, s.trColl, *buf); err != nil {
		return err
	}
	s.logger.Infof("%v traffic records were flushed", bufLen)
	return nil
}

func (s *TrafficRecordStore) recv(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case tr := <-s.trafficReportQueue:
		return s.addSentBytes(ctx, tr)
	}
}

func (s *TrafficRecordStore) addTrafficRecord(tr *structs.TrafficRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()
	select {
	case <-ctx.Done():
		return util.ErrTimeoutWaitingToAddTrafficRecord
	case s.trafficRecordQueue <- tr:
		return nil
	}
}

func (s *TrafficRecordStore) onEvicted(key string, monitor *TrafficMonitor) {
	if monitor == nil {
		return
	}
	ip := monitor.IP
	dir := consts.TRAFFIC_DIR_V4_EGRESS
	monitor.wmMu.RLock()
	dataBytes := monitor.WorldMetrics.SentBytes.Swap(0)
	if dataBytes != 0 {
		tag := fmt.Sprintf("identity:%v", identity.ReservedIdentityWorld)
		tr_id := fmt.Sprintf("%v/%v/%v", ip, tag, dir)
		t := structs.TrafficRecord{
			TrafficRecordMeta: structs.TrafficRecordMetaData{
				Tag: tag,
				Dir: dir,
				IP:  ip,
			},
			DataBytes: dataBytes,
			ID:        tr_id,
			Timestamp: time.Now(),
		}
		if err := s.addTrafficRecord(&t); err != nil {
			s.logger.Errorf("failed to add traffic record: %v", err)
		}
	}
	monitor.wmMu.RUnlock()
	monitor.pmMu.RLock()
	for port, m := range monitor.PortMetrics {
		if m == nil {
			continue
		}
		dataBytes := m.SentBytes.Swap(0)
		if dataBytes == 0 {
			continue
		}
		tag := fmt.Sprintf("port:%v", port)
		tr_id := fmt.Sprintf("%v/%v/%v", ip, tag, dir)
		t := structs.TrafficRecord{
			TrafficRecordMeta: structs.TrafficRecordMetaData{
				Tag: tag,
				Dir: dir,
				IP:  ip,
			},
			DataBytes: dataBytes,
			ID:        tr_id,
			Timestamp: time.Now(),
		}
		if err := s.addTrafficRecord(&t); err != nil {
			s.logger.Errorf("failed to add traffic record: %v", err)
			continue
		}
	}
	monitor.pmMu.RUnlock()
}

func (s *TrafficRecordStore) InitSyncQueue() {
	s.trafficMonitorSync = lru_expirable.NewLRU[string, *TrafficMonitor](s.cfg.MaxMonitorEntriesSize, s.onEvicted, time.Second*time.Duration(s.cfg.MonitorSyncPeriod))
}

func (s *TrafficRecordStore) Init(ctx context.Context) error {
	p := s.p
	var collExists bool
	var err error
	// find the collection we need
	for {
		collExists, err = p.FindColl(ctx, s.trColl)
		if err == nil {
			break
		} else if err == util.ErrPersistentStorageNotReady {
			time.Sleep(time.Millisecond * 100)
		} else {
			return err
		}
	}
	// try to create the collection if it doesn't exist
	if !collExists {
		for {
			err = p.CreateTimeSeriesColl(ctx, s.trColl, TRAFFIC_RECORD_TIME_FIELD, TRAFFIC_RECORD_META_FIELD)
			if err == nil {
				break
			} else if err == util.ErrPersistentStorageNotReady {
				time.Sleep(time.Millisecond * 100)
			} else if err == util.ErrCollectionAlreadyExists {
				// it was already created by other agents
				break
			} else {
				return err
			}
		}
	}
	return nil
}

func (s *TrafficRecordStore) StartWorker(ctx context.Context) error {
	workerEg := errgroup.Group{}
	workerEg.SetLimit(s.cfg.MaxWorkerCount)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			workerEg.Go(func() error {
				return s.flush(ctx)
			})
		}
	}
}

func (s *TrafficRecordStore) StartRecver(ctx context.Context) error {
	recverEg := errgroup.Group{}
	recverEg.SetLimit(s.cfg.MaxRecverCount)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			recverEg.Go(func() error {
				return s.recv(ctx)
			})
		}
	}
}
