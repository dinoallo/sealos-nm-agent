package traffic_record_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/traffic_record"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"github.com/matryer/is"
	"golang.org/x/sync/errgroup"
)

var (
	trs *traffic_record.TrafficRecordStoreInterface
	cfg conf.TrafficRecordStoreConfig
)

func TestFlushing(t *testing.T) {
	t.Run("add a report", func(t *testing.T) {
		is := is.New(t)
		tr := util.GenerateTrafficReport()
		err := trs.AddTrafficReport(context.Background(), tr)
		is.NoErr(err)

	})
	t.Run("add multiple traffic reports", func(t *testing.T) {
		total := 5
		is := is.New(t)
		for i := 0; i < total; i++ {
			tr := util.GenerateTrafficReport()
			err := trs.AddTrafficReport(context.Background(), tr)
			is.NoErr(err)
		}
	})
	t.Run("wait a while for them to flush (check db)", func(t *testing.T) {
		pad := 5
		d := cfg.MonitorSyncPeriod + cfg.MaxRecordWaitingTime + pad
		time.Sleep(time.Second * time.Duration(d))
	})
}

func TestMain(m *testing.M) {
	var dbUri string = os.Getenv(conf.DB_URI_ENV)
	log, err := util.GetLogger(true)
	if err != nil {
		panic(err)
	}
	mainConf, err := conf.InitConfig(log, true)
	if err != nil {
		log.Fatal(err)
	}
	mainEg := errgroup.Group{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pp := persistent.PersistentParam{
		ParentLogger: log,
		DBURI:        dbUri,
	}
	p := persistent.NewPersistentInterface(pp, *mainConf.PersistentStorageConfig)
	p.Launch(ctx, &mainEg)
	trp := traffic_record.TrafficRecordStoreParam{
		ParentLogger: log,
		P:            p,
	}
	trs = traffic_record.NewTrafficRecordStoreInterface(trp, *mainConf.TrafficRecordStoreConfig)
	cfg = *mainConf.TrafficRecordStoreConfig
	trs.Launch(ctx, &mainEg)
	// test starts here
	// fmt.Println(dbUri)
	code := m.Run()
	log.Infof("the test suite return code: %v", code)
	os.Exit(0)
}
