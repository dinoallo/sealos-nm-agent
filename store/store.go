package store

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	lru_expirable "github.com/hashicorp/golang-lru/v2/expirable"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.uber.org/zap"
)

const (
	CACHE_ENTRIES_SIZE = 256
	CACHE_EXPIRED_TIME = time.Second * 3
	MAX_POOL_SIZE      = 100

	COLLECTION_PREFIX     = "traffic_accounts"
	DB_CONNECTION_TIMEOUT = time.Second * 5
)

var (
	NilError error = fmt.Errorf("some arguments or store member variables are nil!!!")
)

type Store struct {
	logger         *zap.SugaredLogger
	trafficReports chan *TrafficReport
	dbClient       *mongo.Client
	cache          *lru_expirable.LRU[string, TrafficAccount]
	database       *mongo.Database
	cred           *DBCred
}

type DBCred struct {
	DBURI string
	DB    string
}

func NewStore(cred *DBCred, baseLogger *zap.SugaredLogger) (*Store, error) {
	if baseLogger == nil {
		return nil, NilError
	}
	if cred == nil {
		return nil, NilError
	}
	reports := make(chan *TrafficReport)

	return &Store{
		logger:         baseLogger,
		trafficReports: reports,
		cred:           cred,
	}, nil
}

func (s *Store) Launch(ctx context.Context, workerCount int) error {
	log := s.logger
	cred := s.cred
	if log == nil || s.cred == nil {
		return NilError
	}
	log.Infof("launch the store...")
	// initialize the database
	clientOps := options.Client().ApplyURI(cred.DBURI).SetMaxPoolSize(MAX_POOL_SIZE)
	if client, err := mongo.Connect(ctx, clientOps); err != nil {
		return err
	} else {
		s.dbClient = client
	}
	if err := s.dbClient.Ping(ctx, readpref.Primary()); err != nil {
		return err
	} else {
		s.database = s.dbClient.Database(cred.DB)
	}

	log.Info("successfully connecting to the database")
	cache := lru_expirable.NewLRU[string, TrafficAccount](CACHE_ENTRIES_SIZE, s.onEvicted, CACHE_EXPIRED_TIME)
	s.cache = cache
	if err := s.initializeCache(ctx); err != nil {
		return err
	}
	log.Info("finished initializing the cache")
	go func(ctx context.Context) {
		defer s.dbClient.Disconnect(context.TODO()) // TODO: is this correctly close the dbClient?
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
	tag := fmt.Sprint(port)
	var ta TrafficAccount
	if found, err := s.getByIP(ctx, addr, &ta); err != nil {
		return err
	} else if found {
		if _, exists := ta.Properties[tag]; !exists {
			pp := Property{}
			ta.Properties[tag] = pp
			s.cache.Remove(addr)
			s.cache.Add(addr, ta)
		}
	} else {
		pps := make(map[string]Property)
		pps[tag] = Property{}
		ta := TrafficAccount{
			IP:         addr,
			Properties: pps,
		}
		s.cache.Add(addr, ta)
	}
	return nil
}

func (s *Store) DumpTraffic(ctx context.Context, addr string, tag string, reset bool) (Property, error) {
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

func (s *Store) initializeCache(ctx context.Context) error {
	if s.dbClient == nil || s.cache == nil {
		return fmt.Errorf("the database client and the cache store cannot be nil!")
	}
	if coll, err := s.getCurrentCollection(); err != nil {
		return err
	} else {
		opts := options.Find().SetLimit(CACHE_ENTRIES_SIZE) //TODO: check me!
		findCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		if cursor, err := coll.Find(findCtx, bson.D{}, opts); err != nil {
			return err
		} else {
			var results []TrafficAccount //TODO: is this marshalling correct?
			if err = cursor.All(ctx, &results); err != nil {
				return err
			}
			for _, result := range results {
				key := result.IP
				s.cache.Add(key, result)
			}
		}
	}
	return nil
}

func (s *Store) processTrafficReport(ctx context.Context, report *TrafficReport) {
	log := s.logger
	// duplicate the data for output usage
	if report.Identity == identity.ReservedIdentityWorld {
		tag := "world"
		if err := s.add(ctx, report, tag); err != nil {
			log.Errorf("failed to update the value: %v", err)
			return
		}
	}

	if err := s.add(ctx, report, ""); err != nil {
		log.Errorf("failed to update the value: %v", err)
		return
	} // log.Infof("the data of ip %v, port %v has been updated", report.LocalIP, report.LocalPort)
	log.Debugf("proto: %v; ident: %v; %v:%v => %v:%v, %v bytes sent;", report.Protocol, report.Identity, report.SrcIP, report.SrcPort, report.DstIP, report.DstPort, report.DataBytes)
}

func (s *Store) RemoveSubscribedPort(ctx context.Context, addr string, port uint32) error {
	if s.cache == nil {
		return NilError
	}

	if coll, err := s.getCurrentCollection(); err != nil {
		return err
	} else {
		tag := fmt.Sprint(port)
		updateCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		filter := bson.D{{
			Key:   "ip",
			Value: addr,
		}}
		key := fmt.Sprintf("properties.%s", tag)
		update := bson.D{{
			Key: "$unset",
			Value: bson.D{{
				Key:   key,
				Value: 1,
			}},
		}}
		if _, err := coll.UpdateOne(updateCtx, filter, update); err != nil {
			return err
		}
	}

	if _, found := s.cache.Get(addr); found {
		s.cache.Remove(addr)
	}

	return nil
}

func (s *Store) DeleteTrafficAccount(ctx context.Context, ipAddr string) error {
	// clean up the cache
	return s.delByIP(ctx, ipAddr)
}

// This can only used for Egress Traffic
func (s *Store) isFromTheSubscribedPorts(ctx context.Context, report *TrafficReport) (bool, error) {
	if s.database == nil {
		return false, fmt.Errorf("the database shouldn't be nil")
	}
	var ip string
	var tag string
	if report.Dir == V4Ingress {
		ip = report.DstIP.String()
		tag = fmt.Sprint(report.SrcPort)
	} else if report.Dir == V4Egress {
		ip = report.SrcIP.String()
		tag = fmt.Sprint(report.SrcPort)
	} else {
		return false, nil
	}
	var ta TrafficAccount
	if ok, err := s.getByIP(ctx, ip, &ta); err != nil {
		return false, err
	} else if ok {
		if _, exists := ta.Properties[tag]; exists {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) add(ctx context.Context, report *TrafficReport, altTag string) error {
	db := s.database
	if db == nil || report == nil {
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

func (s *Store) onEvicted(key string, value TrafficAccount) {
	logger := s.logger
	if s.logger == nil {
		//!?
		return
	}
	if coll, err := s.getCurrentCollection(); err != nil {
		logger.Errorf("unable to evict the cache entry: %v", err)
		return
	} else {
		putCtx, cancel := context.WithTimeout(context.TODO(), DB_CONNECTION_TIMEOUT)
		defer cancel()
		opts := options.Replace().SetUpsert(true)
		filter := bson.D{{
			Key:   "ip",
			Value: key,
		}}
		replacement := value
		if _, err := coll.ReplaceOne(putCtx, filter, replacement, opts); err != nil {
			logger.Errorf("unable to evict the cache entry: %v", err)
			return
		}
	}
}

func (s *Store) getByIP(ctx context.Context, ip string, ta *TrafficAccount) (bool, error) {
	if ta == nil {
		return false, fmt.Errorf("a TrafficAccount should be created")
	}
	found := false
	if _ta, ok := s.cache.Get(ip); ok {
		*ta = _ta
		found = true
	} else {
		getCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		if coll, err := s.getCurrentCollection(); err != nil {
			return false, err
		} else {
			filter := bson.D{
				{
					Key:   "ip",
					Value: ip,
				},
			}
			if err := coll.FindOne(getCtx, filter).Decode(ta); err != nil {
				if err != mongo.ErrNoDocuments {
					return false, err
				}
			} else {
				found = true
				s.cache.Add(ip, *ta)
			}
		}
	}
	return found, nil
}

func (s *Store) delByIP(ctx context.Context, ip string) error {
	s.cache.Remove(ip)
	if coll, err := s.getCurrentCollection(); err != nil {
		return err
	} else {
		delCtx, cancel := context.WithTimeout(ctx, DB_CONNECTION_TIMEOUT)
		defer cancel()
		filter := bson.D{{
			Key:   "ip",
			Value: ip,
		}}
		if _, err := coll.DeleteOne(delCtx, filter); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) getCurrentCollection() (*mongo.Collection, error) {
	db := s.database
	if db == nil {
		return nil, fmt.Errorf("the database shouldn't be nil")
	}
	now := time.Now()
	timeSuffix := fmt.Sprintf("%s%s%s", fmt.Sprint(now.Year()), fmt.Sprint(int(now.Month())), fmt.Sprint(now.Day()))
	collName := fmt.Sprintf("%s_%s", COLLECTION_PREFIX, timeSuffix)
	coll := db.Collection(collName)
	return coll, nil
}
