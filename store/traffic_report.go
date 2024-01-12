package store

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type TrafficReportStore struct {
	name           string
	logger         *zap.SugaredLogger
	manager        *StoreManager
	trafficReports chan *TrafficReport
}

func NewTrafficReportStore(baseLogger *zap.SugaredLogger) (*TrafficReportStore, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	trafficReports := make(chan *TrafficReport)
	return &TrafficReportStore{
		name:           "traffic_reports",
		logger:         baseLogger.With(zap.String("component", "traffic_account_store")),
		trafficReports: trafficReports,
	}, nil
}

func (s *TrafficReportStore) AddTrafficReport(ctx context.Context, report *TrafficReport) error {
	s.trafficReports <- report
	return nil
}

func (s *TrafficReportStore) processTrafficReport(ctx context.Context, report *TrafficReport) error {
	log := s.logger
	if report == nil {
		return util.ErrTrafficReportNotInited
	}
	if s.manager == nil {
		return util.ErrStoreManagerNotInited
	}
	ps := s.manager.ps
	if ps == nil {
		return util.ErrPersistentStorageNotInited
	}
	if err := ps.insertOne(ctx, TRCollection, *report); err != nil {
		return err

	}
	log.Debugf("report stored. proto: %v; ident: %v; %v:%v => %v:%v, %v bytes sent;", report.Protocol, report.Identity, report.TrafficReportMeta.SrcIP, report.TrafficReportMeta.SrcPort, report.TrafficReportMeta.DstIP, report.TrafficReportMeta.DstPort, report.DataBytes)
	return nil
}

func (s *TrafficReportStore) initCache(ctx context.Context) error {
	return nil
}

func (s *TrafficReportStore) setManager(manager *StoreManager) error {
	if manager == nil {
		return util.ErrStoreManagerNotInited
	}
	s.manager = manager
	return nil
}

func (s *TrafficReportStore) getName() string {
	return s.name
}

func (s *TrafficReportStore) launch(ctx context.Context, eg *errgroup.Group, workerCount int) error {
	if s.manager == nil {
		return util.ErrStoreManagerNotInited
	}
	if s.manager.ps == nil {
		return util.ErrPersistentStorageNotInited
	}
	if found, err := s.manager.ps.findCollection(ctx, TRCollection); err != nil {
		return err
	} else if !found {
		metaField := TRAFFIC_REPORT_META_FIELD
		if err := s.manager.ps.createTSDB(ctx, TRCollection, TRAFFIC_REPORT_TIME_FIELD, &metaField); err != nil {
			return err
		}
	}
	for i := 0; i < workerCount; i++ {
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case report := <-s.trafficReports:
					if err := s.processTrafficReport(ctx, report); err != nil {
						return err
					}
				}
			}
		})
	}
	return nil

}
