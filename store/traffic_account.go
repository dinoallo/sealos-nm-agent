package store

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type TrafficAccountStore struct {
	name           string
	logger         *zap.SugaredLogger
	manager        *StoreManager
	cache          *lru_expirable.LRU[string, TrafficAccount]
	trafficReports chan *TrafficReport
}

func NewTrafficAccountStore(baseLogger *zap.SugaredLogger) (*TrafficAccountStore, error) {
	if baseLogger == nil {
		return nil, util.ErrParentLoggerNotInited
	}
	trafficReports := make(chan *TrafficReport)
	return &TrafficAccountStore{
		name:           "traffic_accounts",
		logger:         baseLogger.With(zap.String("component", "traffic_account_store")),
		trafficReports: trafficReports,
	}, nil
}

func (s *TrafficAccountStore) AddTrafficReport(ctx context.Context, report *TrafficReport) error {
	s.trafficReports <- report
	return nil
}

func (s *TrafficAccountStore) DumpTraffic(ctx context.Context, addr string, tag string, reset bool) (Property, error) {
	var ta TrafficAccount
	p := Property{
		SentBytes: 0,
		RecvBytes: 0,
	}
	if found, err := s.getByIP(ctx, addr, &ta); err != nil {
		return p, err
	} else if found {
		if _, ok := ta.Properties[tag]; ok {
			p = ta.Properties[tag]
			if reset {
				ta.Properties[tag] = Property{
					SentBytes: 0,
					RecvBytes: 0,
				}
			}
		}
	}
	return p, nil
}

func (s *TrafficAccountStore) processTrafficReport(ctx context.Context, report *TrafficReport) error {
	log := s.logger
	// duplicate the data for output usage
	if report.Identity == identity.ReservedIdentityWorld {
		tag := "world"
		if err := s.add(ctx, report, tag); err != nil {
			return err
		}
	}

	if err := s.add(ctx, report, ""); err != nil {
		return err
	} // log.Infof("the data of ip %v, port %v has been updated", report.LocalIP, report.LocalPort)
	log.Debugf("proto: %v; ident: %v; %v:%v => %v:%v, %v bytes sent;", report.Protocol, report.Identity, report.SrcIP, report.SrcPort, report.DstIP, report.DstPort, report.DataBytes)
	return nil
}

func (s *TrafficAccountStore) DeleteTrafficAccount(ctx context.Context, ipAddr string) error {
	// clean up the cache
	return s.delByIP(ctx, ipAddr)
}

func (s *TrafficAccountStore) add(ctx context.Context, report *TrafficReport, altTag string) error {
	if report == nil {
		return fmt.Errorf("the database or the report shouldn't be nil")
	}
	var ta TrafficAccount
	pp := Property{
		SentBytes: 0,
		RecvBytes: 0,
	}
	dir := report.Dir
	value := uint64(report.DataBytes)
	var ip string
	var tag string
	if dir == V4Egress {
		pp.SentBytes += value
		ip = report.SrcIP.String()
		tag = fmt.Sprint(report.SrcPort)
	} else if dir == V4Ingress {
		pp.RecvBytes += value
		ip = report.DstIP.String()
		tag = fmt.Sprint(report.DstPort)
	} else {
		return nil
	}
	if altTag != "" {
		tag = altTag
	}
	if found, err := s.getByIP(ctx, ip, &ta); err != nil {
		return err
	} else {
		if found {
			if _, exists := ta.Properties[tag]; exists {
				_pp := ta.Properties[tag]
				pp.SentBytes += _pp.SentBytes
				pp.RecvBytes += _pp.RecvBytes
			}
			ta.Properties[tag] = pp
		} else {
			ta = TrafficAccount{
				IP:         ip,
				Properties: map[string]Property{tag: pp},
			}
		}
		s.cache.Add(ip, ta)
	}
	return nil
}

func (s *TrafficAccountStore) getByIP(ctx context.Context, ip string, ta *TrafficAccount) (bool, error) {
	if ta == nil {
		return false, fmt.Errorf("a TrafficAccount should be created")
	}
	found := false
	if _ta, ok := s.cache.Get(ip); ok {
		*ta = _ta
		found = true
	} else {
		p := s.manager.ps
		if p == nil {
			return false, util.ErrPersistentStorageNotInited
		}
		if ok, err := p.findOne(ctx, TACollection, "ip", ip, ta); err != nil {
			return false, err
		} else if ok {
			found = true
			s.cache.Add(ip, *ta)
		}
	}
	return found, nil
}

func (s *TrafficAccountStore) delByIP(ctx context.Context, ip string) error {
	s.cache.Remove(ip)
	p := s.manager.ps
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	if err := p.deleteOne(ctx, TACollection, "ip", ip); err != nil {
		return err
	}

	return nil
}

func (s *TrafficAccountStore) initCache(ctx context.Context) error {
	p := s.manager.ps
	if p == nil {
		return util.ErrPersistentStorageNotInited
	}
	cache := lru_expirable.NewLRU[string, TrafficAccount](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_EXPIRED_TIME)
	s.cache = cache
	var results []TrafficAccount
	if err := p.findAll(ctx, TACollection, CACHE_ENTRIES_SIZE, &results); err != nil {
		return err
	} else {
		for _, result := range results {
			key := result.IP
			s.cache.Add(key, result)
		}
	}
	return nil
}

func (s *TrafficAccountStore) onEvicted(key string, value TrafficAccount) {
	logger := s.logger
	p := s.manager.ps
	if s.logger == nil {
		//!?
		return
	}
	if p != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
		defer cancel()
		if err := p.replaceOne(ctx, TACollection, "ip", key, value); err != nil {
			logger.Errorf("unable to evicted the traffic account: %v", err)
		}
	} else {
		logger.Errorf("eviction failed: %v", util.ErrPersistentStorageNotInited)
	}
}

func (s *TrafficAccountStore) setManager(manager *StoreManager) error {
	if manager == nil {
		return util.ErrStoreManagerNotInited
	}
	s.manager = manager
	return nil
}

func (s *TrafficAccountStore) getName() string {
	return s.name
}

func (s *TrafficAccountStore) launch(ctx context.Context, eg *errgroup.Group, workerCount int) error {
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
