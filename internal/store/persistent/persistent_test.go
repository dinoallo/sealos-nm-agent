package persistent_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	is "github.com/matryer/is"
	"golang.org/x/sync/errgroup"
)

var (
	p *persistent.PersistentInterface
)

func TestCollectionUtils(t *testing.T) {
	collName := fmt.Sprintf("test_%v", time.Now().Unix())
	coll := store.Coll{
		T:    store.COLL_TYPE_OTHER,
		Name: collName,
	}
	is := is.New(t)
	t.Run("find non-existent collection", func(t *testing.T) {
		is := is.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		found, err := p.FindColl(ctx, coll)
		is.NoErr(err)
		is.True(!found)
	})
	t.Run("create a time series new collection", func(t *testing.T) {
		is := is.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		tf := "timestamp"
		mf := "meta"
		err := p.CreateTimeSeriesColl(ctx, coll, tf, mf)
		is.NoErr(err)
	})
	t.Run("find the created collection", func(t *testing.T) {
		is := is.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		found, err := p.FindColl(ctx, coll)
		is.NoErr(err)
		is.True(found)
	})
}

func TestPartialTTLIndexUtils(t *testing.T) {
	collName := fmt.Sprintf("pti_test_%v", time.Now().Unix())
	ptiName := "stale"
	coll := store.Coll{
		T:    store.COLL_TYPE_OTHER,
		Name: collName,
	}
	t.Run("find a non existent partial ttl index", func(t *testing.T) {
		is := is.New(t)
		found, err := p.FindPartialTTLIndex(context.Background(), coll, ptiName)
		is.NoErr(err)
		is.True(!found)
	})
	t.Run("create the partial ttl index", func(t *testing.T) {
		is := is.New(t)
		err := p.CreatePartialTTLIndex(context.Background(), coll, ptiName)
		is.NoErr(err)
	})
	t.Run("find the created partial ttl index", func(t *testing.T) {
		is := is.New(t)
		found, err := p.FindPartialTTLIndex(context.Background(), coll, ptiName)
		is.NoErr(err)
		is.True(found)
	})
}

func TestInsertItemUtils(t *testing.T) {
	collName := fmt.Sprintf("insert_test_%v", time.Now().Unix())
	coll := store.Coll{
		T:    store.COLL_TYPE_OTHER,
		Name: collName,
	}
	t.Run("insert many items", func(t *testing.T) {
		is := is.New(t)
		var buf []any
		for i := 0; i < 5; i++ {
			tr := util.GenerateTrafficRecord()
			buf = append(buf, tr)
		}
		err := p.InsertMany(context.Background(), coll, buf)
		is.NoErr(err)
	})
}

func TestFindItemUtils(t *testing.T) {
	collName := fmt.Sprintf("find_test_%v", time.Now().Unix())
	coll := store.Coll{
		T:    store.COLL_TYPE_OTHER,
		Name: collName,
	}
	total := 5
	t.Run("insert many traffic records for testing", func(t *testing.T) {
		is := is.New(t)
		var buf []any
		for i := 0; i < total; i++ {
			tr := util.GenerateTrafficRecord()
			buf = append(buf, tr)
		}
		err := p.InsertMany(context.Background(), coll, buf)
		is.NoErr(err)
	})
	var items []structs.TrafficRecord
	t.Run("find all traffic records", func(t *testing.T) {
		is := is.New(t)
		err := p.FindAll(context.Background(), coll, &items)
		is.NoErr(err)
		is.True(total == len(items)) // not able to return all items
	})
	t.Run("find one of them", func(t *testing.T) {
		is := is.New(t)
		if len(items) < 1 {
			is.Fail()
		}
		trSample := items[0]
		var tr structs.TrafficRecord
		err := p.FindOne(context.Background(), coll, "tr_id", trSample.ID, &tr)
		is.NoErr(err)
		is.True(tr.ID == trSample.ID)
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
	p = persistent.NewPersistentInterface(pp, *mainConf.PersistentStorageConfig)
	p.Launch(ctx, &mainEg)
	// test starts here
	// fmt.Println(dbUri)
	code := m.Run()
	log.Infof("the test suite return code: %v", code)
	os.Exit(0)
}
