package store

import (
	"context"
	"fmt"
	"strconv"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

type Store struct {
	logger         *zap.SugaredLogger
	trafficReports chan *TrafficReport
	dbClient       *clientv3.Client
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
	byteFieldKey := constructKeyByIPandPort(report.LocalIP.String(), fmt.Sprint(report.LocalPort), byteField, report.RemoteIP.String(), fmt.Sprint(report.RemotePort), false)
	identityKey := constructKeyByIdentity(report.LocalIP.String(), fmt.Sprint(report.Identity), byteField, false)
	value := uint64(report.DataBytes)
	if err := s.add(ctx, byteFieldKey, value); err != nil {
		log.Errorf("failed to update the value for key %v: %v", byteFieldKey, err)
		return
	}
	if err := s.add(ctx, identityKey, value); err != nil {
		log.Errorf("failed to update the value for key %v: %v", identityKey, err)
		return
	}
	// duplicate the data for output usage
	byteFieldKey = constructKeyByIPandPort(report.LocalIP.String(), fmt.Sprint(report.LocalPort), byteField, report.RemoteIP.String(), fmt.Sprint(report.RemotePort), true)
	identityKey = constructKeyByIdentity(report.LocalIP.String(), fmt.Sprint(report.Identity), byteField, true)
	if err := s.add(ctx, byteFieldKey, value); err != nil {
		log.Errorf("failed to output the value for key %v: %v", byteFieldKey, err)
		return
	}
	if err := s.add(ctx, identityKey, value); err != nil {
		log.Errorf("failed to output the value for key %v: %v", identityKey, err)
		return
	}
	// log.Infof("the data of ip %v, port %v has been updated", report.LocalIP, report.LocalPort)
}

func (s *Store) DeleteTrafficAccount(ctx context.Context, ipAddr string) error {
	prefix := constructPrefixByAccountIP(ipAddr)
	return s.delByPrefix(ctx, prefix)
}

func (s *Store) add(ctx context.Context, key string, value uint64) error {
	dbClient := s.dbClient
	log := s.logger.With(zap.String("key", key))
	getCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	resp, err := dbClient.Get(getCtx, key)
	if err != nil {
		log.Errorf("failed to get the field: %v", err)
		return err
	}
	for _, kv := range resp.Kvs {
		if v, err := strconv.ParseUint(string(kv.Value), 10, 64); err != nil {
			log.Errorf("failed to parse the byteField from the database: %v", err)
			return err
		} else {
			value += v
		}
	}
	putCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	if _, err := dbClient.Put(putCtx, key, fmt.Sprint(value)); err != nil {
		log.Errorf("failed to update the byteField: %v", err)
		return err
	}
	return nil
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
