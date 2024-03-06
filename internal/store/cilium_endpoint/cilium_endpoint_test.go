package cilium_endpoint

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"context"
	"os"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"github.com/matryer/is"
	"golang.org/x/sync/errgroup"
)

var (
	ces *CiliumEndpointStoreInterface
	cfg conf.CiliumEndpointStoreConfig
)

// NOTICE: please use a fitting(longer) EndpointSyncPeriod
func TestCreate(t *testing.T) {
	node := ces.h.getCurrentNode()
	t.Run("create a cilium endpoint", func(t *testing.T) {
		is := is.New(t)
		eid := rand.Int63n(1000)
		fmt.Printf("random eid for TestCreate: %v\n", eid)
		key := ces.h.getKey(eid, node)
		err := ces.Create(context.Background(), eid)
		is.NoErr(err)
		cep, ok := ces.h.cepCache.Get(key)
		if !ok {
			is.Fail()
		}
		is.True(!cep.CreatedTime.IsZero())
	})
}

func TestRemove(t *testing.T) {
	eid1 := rand.Int63n(1000)
	eid2 := rand.Int63n(1000)
	fmt.Printf("random eid1 for TestRemove: %v\n", eid1)
	fmt.Printf("random eid2 for TestRemove: %v\n", eid2)
	node := ces.h.getCurrentNode()
	t.Run("create a cilium endpoint with eid1 to remove", func(t *testing.T) {
		is := is.New(t)
		err := ces.Create(context.Background(), eid1)
		is.NoErr(err)
	})
	t.Run("remove a cilium endpoint that's in the cache", func(t *testing.T) {
		is := is.New(t)
		err := ces.RemoveCEP(context.Background(), eid1)
		is.NoErr(err)
		key := ces.h.getKey(eid1, node)
		cep, ok := ces.h.cepCache.Get(key)
		if !ok {
			is.Fail()
		}
		is.True(!cep.DeletedTime.IsZero())
	})
	t.Run("create a cilium endpoint with eid2 to remove", func(t *testing.T) {
		is := is.New(t)
		err := ces.Create(context.Background(), eid2)
		is.NoErr(err)
	})
	t.Run("wait a while for it to update in the database", func(t *testing.T) {
		pad := 1
		d := cfg.EndpointSyncPeriod + pad
		time.Sleep(time.Second * time.Duration(d))
	})
	t.Run("remove a cilium endpoint that's in the database", func(t *testing.T) {
		is := is.New(t)
		err := ces.RemoveCEP(context.Background(), eid2)
		is.NoErr(err)
		key := ces.h.getKey(eid2, node)
		cep, ok := ces.h.cepCache.Get(key)
		if !ok {
			is.Fail()
		}
		is.True(!cep.DeletedTime.IsZero())
	})
}

func TestFind(t *testing.T) {
	eid1 := rand.Int63n(1000)
	eid2 := rand.Int63n(1000)
	fmt.Printf("random eid1 for TestFind: %v\n", eid1)
	fmt.Printf("random eid2 for TestFind: %v\n", eid2)
	node := ces.h.getCurrentNode()
	t.Run("create a cilium endpoint with eid1 to find", func(t *testing.T) {
		is := is.New(t)
		err := ces.Create(context.Background(), eid1)
		is.NoErr(err)
	})
	t.Run("find a cilium endpoint that's in the cache", func(t *testing.T) {
		is := is.New(t)
		found, err := ces.FindCEP(context.Background(), eid1)
		is.NoErr(err)
		key := ces.h.getKey(eid1, node)
		_, ok := ces.h.cepCache.Get(key)
		if !ok {
			is.Fail()
		}
		is.True(found)
	})
	t.Run("create a cilium endpoint with eid2 to find", func(t *testing.T) {
		is := is.New(t)
		err := ces.Create(context.Background(), eid2)
		is.NoErr(err)
	})
	t.Run("wait a while for it to update in the database", func(t *testing.T) {
		pad := 1
		d := cfg.EndpointSyncPeriod + pad
		time.Sleep(time.Second * time.Duration(d))
	})
	t.Run("find a cilium endpoint that's in the database", func(t *testing.T) {
		is := is.New(t)
		found, err := ces.FindCEP(context.Background(), eid2)
		is.NoErr(err)
		key := ces.h.getKey(eid2, node)
		_, ok := ces.h.cepCache.Get(key)
		if !ok {
			is.Fail()
		}
		is.True(found)
	})
}

func TestGet(t *testing.T) {
	total := 5
	t.Run("create cilium endpoints", func(t *testing.T) {
		is := is.New(t)
		for i := 0; i < total; i++ {
			eid := rand.Int63n(1000)
			fmt.Printf("random eid for TestGet: %v\n", eid)
			err := ces.Create(context.Background(), eid)
			is.NoErr(err)
		}
	})
	t.Run("wait a while for it to update in the database", func(t *testing.T) {
		pad := 1
		d := cfg.EndpointSyncPeriod + pad
		time.Sleep(time.Second * time.Duration(d))
	})
	t.Run("get all cilium endpoints", func(t *testing.T) {
		var ceps []structs.CiliumEndpoint
		is := is.New(t)
		err := ces.GetAllCEPs(context.Background(), &ceps)
		is.NoErr(err)
		is.True(len(ceps) >= total) //TODO: find a better way to test this
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
	cp := CiliumEndpointStoreParam{
		ParentLogger: log,
		P:            p,
	}
	ces = NewCiliumEndpointStoreInterface(cp, *mainConf.CiliumEndpointStoreConfig)
	cfg = *mainConf.CiliumEndpointStoreConfig
	ces.Launch(ctx, &mainEg)
	// test starts here
	// fmt.Println(dbUri)
	code := m.Run()
	log.Infof("the test suite return code: %v", code)
	os.Exit(0)
}
