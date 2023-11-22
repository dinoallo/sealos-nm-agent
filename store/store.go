package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	lru "github.com/hashicorp/golang-lru/v2"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

type Store struct {
	logger         *zap.SugaredLogger
	trafficReports chan *TrafficReport
	dbClient       *clientv3.Client
	cache          *lru.Cache[string, uint64]
	host           string
	port           string
}

func NewStore(dbHost string, dbPort string, baseLogger *zap.SugaredLogger) (*Store, error) {
	if baseLogger == nil {
		return nil, fmt.Errorf("the base logger shouldn't be nil")
	}
	reports := make(chan *TrafficReport)

	return &Store{
		logger:         baseLogger,
		trafficReports: reports,
		host:           dbHost,
		port:           dbPort,
	}, nil
}

func (s *Store) Launch(ctx context.Context, workerCount int) error {
	log := s.logger
	log.Infof("launch the store")
	dbEndpoint := fmt.Sprintf("%s:%s", s.host, s.port)
	dbClient, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{dbEndpoint},
		DialTimeout: 2 * time.Second,
	})
	s.dbClient = dbClient
	if err != nil {
		log.Errorf("failed to connect to the database on %v: %v", dbEndpoint, err)
		return err
	}
	log.Info("successfully connecting to the database")
	cache, err := lru.NewWithEvict[string, uint64](128, s.onEvicted) //TODO: check the size
	if err != nil {
		return err
	}
	s.cache = cache

	if err := s.initializeCache(ctx); err != nil {
		return err
	}
	go func(ctx context.Context) {
		defer dbClient.Close()
		<-ctx.Done()
	}(ctx)
	for i := 0; i < workerCount; i++ {
		go func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					return
				case report := <-s.trafficReports:
					s.processTrafficReport(ctx, report)
				}
			}
		}(ctx)
	}

	return nil
}

func (s *Store) AddTrafficReport(ctx context.Context, report *TrafficReport) error {
	s.trafficReports <- report
	return nil
}

func (s *Store) AddSubscribedPort(ctx context.Context, addr string, port uint32) error {
	key := getKeyForExposedPortOfTheAddr(addr, fmt.Sprint(port))
	s.cache.Add(key, 1)
	return nil
}

func (s *Store) initializeCache(ctx context.Context) error {
	if s.dbClient == nil || s.cache == nil {
		return fmt.Errorf("the database client and the cache store cannot be nil!")
	}
	dbClient := s.dbClient
	getCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	prefix := "/nm-agent/"
	if resp, err := dbClient.Get(getCtx, prefix, clientv3.WithPrefix()); err != nil {
		return err
	} else {
		for _, kv := range resp.Kvs {
			if value, err := strconv.ParseUint(string(kv.Value), 10, 64); err != nil {
				return err
			} else {
				key := string(kv.Key)
				s.cache.Add(key, value)
			}
		}
	}
	return nil
}

func (s *Store) processTrafficReport(ctx context.Context, report *TrafficReport) {
	log := s.logger
	var byteField string
	switch report.Dir {
	case V4Ingress:
		byteField = "recvBytes"
	case V4Egress:
		byteField = "sentBytes"
	default:
		log.Infof("unknown direction when process traffic")
		return
	}
	value := uint64(report.DataBytes)
	// duplicate the data for output usage
	if report.Identity == identity.ReservedIdentityWorld {
		identityKey := constructKeyByIdentity(report.LocalIP.String(), fmt.Sprint(report.Identity), byteField, false)
		log.Debugf("protocol: %v; identity: %v; %v => %v, %v bytes sent;", report.Protocol, report.Identity, report.LocalIP, report.RemoteIP, report.DataBytes)
		if err := s.add(ctx, identityKey, value); err != nil {
			log.Errorf("failed to output the value for key %v: %v", identityKey, err)
			return
		}
	}
	if ok, err := s.isFromTheExposedPorts(ctx, report); err != nil {
		log.Errorf("failed to check if the port is exposed: %v", err)
		return
	} else if ok {
		byteFieldKey := constructKeyByIPandPort(report.LocalIP.String(), fmt.Sprint(report.LocalPort), byteField, report.RemoteIP.String(), fmt.Sprint(report.RemotePort), false)
		log.Debugf("protocol: %v; identity: %v; %v => %v, %v bytes sent;", report.Protocol, report.Identity, report.LocalIP, report.RemoteIP, report.DataBytes)
		if err := s.add(ctx, byteFieldKey, value); err != nil {
			log.Errorf("failed to output the value for key %v: %v", byteFieldKey, err)
			return
		}
	}
	// log.Infof("the data of ip %v, port %v has been updated", report.LocalIP, report.LocalPort)
}

func (s *Store) DeleteTrafficAccount(ctx context.Context, ipAddr string) error {
	// clean up the cache
	keys := s.cache.Keys()
	for _, key := range keys {
		if strings.Contains(key, ipAddr) {
			s.cache.Remove(key)
		}
	}
	prefix := constructPrefixByAccountIP(ipAddr)
	return s.delByPrefix(ctx, prefix)
}

func (s *Store) isFromTheExposedPorts(ctx context.Context, report *TrafficReport) (bool, error) {
	log := s.logger
	dbClient := s.dbClient
	getCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	port := report.LocalPort
	addr := report.LocalIP
	key := getKeyForExposedPortOfTheAddr(addr.String(), fmt.Sprint(port))
	var flag bool = false
	if _, ok := s.cache.Get(key); ok {
		flag = true
	} else {
		if resp, err := dbClient.Get(getCtx, key); err != nil {
			log.Errorf("unable to get the data: %v", err)
			flag = false
		} else if len(resp.Kvs) > 0 {
			flag = true
			s.cache.Add(key, 1)
		}
	}

	return flag, nil
}

func (s *Store) add(ctx context.Context, key string, value uint64) error {
	dbClient := s.dbClient
	log := s.logger.With(zap.String("key", key))
	var originalValue uint64 = 0
	var total uint64 = 0
	if v, ok := s.cache.Get(key); ok {
		originalValue += v
	} else {
		getCtx, cancel := context.WithTimeout(ctx, time.Second*1)
		defer cancel()
		resp, err := dbClient.Get(getCtx, key)
		if err != nil {
			log.Errorf("failed to get the field: %v", err)
			return err
		}
		if len(resp.Kvs) > 0 {
			if v, err := strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64); err != nil {
				log.Errorf("failed to parse the byteField from the database: %v", err)
				return err
			} else {
				originalValue += v
			}
		}
	}
	total = originalValue + value
	s.cache.Add(key, total)
	return nil
}

func (s *Store) onEvicted(key string, value uint64) {
	dbClient := s.dbClient
	log := s.logger
	putCtx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()
	if _, err := dbClient.Put(putCtx, key, fmt.Sprint(value)); err != nil {
		log.Errorf("failed to store the data back to the database: %v", err)
	}
}

func (s *Store) put(ctx context.Context, key string, value uint64) error {
	dbClient := s.dbClient
	log := s.logger.With(zap.String("key", key))
	putCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	if _, err := dbClient.Put(putCtx, key, fmt.Sprint(value)); err != nil {
		log.Errorf("failed to update the byteField: %v", err)
		return err
	}
	return nil
}

func (s *Store) delByPrefix(ctx context.Context, prefix string) error {
	dbClient := s.dbClient
	log := s.logger.With(zap.String("prefix", prefix))
	delCtx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	if _, err := dbClient.Delete(delCtx, prefix, clientv3.WithPrefix()); err != nil {
		log.Errorf("failed to update the byteField: %v", err)
		return err
	}
	return nil
}

func constructKeyByIdentity(localIP string, identity string, field string, forOutput bool) string {
	var prefix string = "nm-agent"
	if forOutput {
		prefix = "nm-agent-output"
	}
	return fmt.Sprintf("/%v/traffic_accounts/ips/%v/%v/identities/%v", prefix, localIP, field, identity)
}

func constructKeyByIPandPort(localIP string, localPort string, field string, remoteIP string, remotePort string, forOutput bool) string {
	// "/nm-agent/traffic_accounts/ips/%v/ports/%v/sentBytes/remote_ips/%v/remote_ports/%v"
	var prefix string = "nm-agent"
	if forOutput {
		prefix = "nm-agent-output"
	}
	return fmt.Sprintf("/%v/traffic_accounts/ips/%v/ports/%v/%v/remote_ips/%v/remote_ports/%v", prefix, localIP, localPort, field, remoteIP, remotePort)
}

func constructPrefixByAccountIP(ipAddr string) string {
	return fmt.Sprintf("/nm-agent/traffic_accounts/ips/%v/", ipAddr)
}

func getKeyForExposedPortOfTheAddr(addr string, port string) string {
	return fmt.Sprintf("/nm-agent/subscription_info/addresses/%v/exposed_ports/%v", addr, port)

}
