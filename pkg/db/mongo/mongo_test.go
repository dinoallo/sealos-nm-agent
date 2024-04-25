package mongo

import (
	//	"fmt"
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"

	// islib "github.com/matryer/is"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/common"
	zaplog "github.com/dinoallo/sealos-networkmanager-agent/pkg/log/zap"
	"github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/require"
	//	"go.mongodb.org/mongo-driver/bson"
)

var (
	db  *Mongo
	now time.Time = time.Now()
)

// func TestPartialTTLIndexOperations(t *testing.T) {
// 	existing_coll := getARandomColl("partial_ttl")
// 	keys := &common.Selector{
// 		Op: common.SelectorEq,
// 		K:  "timestamp",
// 		V:  1,
// 	}
// 	expre := &common.Selector{
// 		Op: common.SelectorGt,
// 		K:  "timestamp",
// 		V:  time.Time{},
// 	}
// 	opts := common.PartialTTLIndexOpts{
// 		PartialTTLIndexName:     "ttl",
// 		IndexKeys:               keys,
// 		PartialFilterExpression: expre,
// 		ExpireAfter:             3600,
// 	}
// 	ctx := context.Background()
// 	t.Run("create a partial ttl index", func(t *testing.T) {
// 		err := db.CreatePartialTTLIndex(ctx, existing_coll, opts)
// 		assert.NoError(t, err)
// 	})
// 	t.Run("find this partial ttl index", func(t *testing.T) {
// 		exists, err := db.FindPartialTTLIndex(ctx, existing_coll, opts)
// 		if assert.NoError(t, err) {
// 			assert.Equal(t, true, exists)
// 		}
// 	})
// 	t.Run("find a non-existing partial ttl index", func(t *testing.T) {
// 		opts.PartialTTLIndexName = "not_a_ttl"
// 		exists, err := db.FindPartialTTLIndex(ctx, existing_coll, opts)
// 		if assert.NoError(t, err) {
// 			assert.Equal(t, false, exists)
// 		}
// 	})
// }

func TestCollectionFinding(t *testing.T) {
	existing_coll := getARandomColl("find_this")
	non_existing_coll := "not_a_test_coll"
	ctx := context.Background()
	// t.Logf("existing_coll: %v", existing_coll)
	t.Run("insert something into the collection", func(t *testing.T) {
		item := TestItem{
			Meta: TestMeta{
				M1: 233,
				M2: 0,
			},
			Timestamp: time.Now(),
			Data:      rand.Int31(),
		}
		err := db.Insert(ctx, existing_coll, []any{&item})
		assert.NoError(t, err)
	})
	t.Run("find an existing collection", func(t *testing.T) {
		exists, err := db.FindColl(ctx, existing_coll)
		if assert.NoError(t, err) {
			assert.Equal(t, true, exists)
		}
	})
	t.Run("find a non-existing collection", func(t *testing.T) {
		exists, err := db.FindColl(ctx, non_existing_coll)
		if assert.NoError(t, err) {
			assert.Equal(t, false, exists)
		}
	})
}

func TestTimeSeriesCollCreating(t *testing.T) {
	timeSeriesColl := getARandomColl("time_series")
	opts := common.TimeSeriesOpts{
		TimeField:   "time",
		MetaField:   "meta",
		ExpireAfter: 3600,
	}
	ctx := context.Background()
	t.Run("create a time series collection", func(t *testing.T) {
		err := db.CreateTimeSeriesColl(ctx, timeSeriesColl, opts)
		assert.NoError(t, err)
	})
	t.Run("find this time series collection", func(t *testing.T) {
		exists, err := db.FindColl(ctx, timeSeriesColl)
		if assert.NoError(t, err) {
			assert.Equal(t, true, exists)
		}
	})
}

func TestCreating(t *testing.T) {
	ctx := context.Background()
	collName := getARandomColl("insert")
	t.Run("insert multiple items", func(t *testing.T) {
		batchSize := 10
		items := generateBatchTestItems(batchSize)
		err := db.Insert(ctx, collName, items)
		assert.NoError(t, err)
	})
}

func TestRequestingOne(t *testing.T) {
	ctx := context.Background()
	collName := getARandomColl("request")
	t.Logf("the collection used for this testing is %v", collName)
	expectedItem := TestItem{
		Meta: TestMeta{
			M1: 233,
			M2: 0,
		},
		Timestamp: time.Now(),
		Data:      rand.Int31(),
	}
	t.Run("insert only one item", func(t *testing.T) {
		err := db.Insert(ctx, collName, []any{&expectedItem})
		assert.NoError(t, err)
	})
	t.Run("get one existing item", func(t *testing.T) {
		var actualItem TestItem
		selector := common.Selector{
			K: "meta.m1",
			V: 233,
		}
		exists, err := db.GetOne(ctx, collName, selector, &actualItem)
		if assert.NoError(t, err) {
			assert.Equal(t, true, exists)
		}
	})

	t.Run("get one non-existing item", func(t *testing.T) {
		selector := common.Selector{
			K: "meta.m2",
			V: 1,
		}
		var actualItem TestItem
		exists, err := db.GetOne(ctx, collName, selector, actualItem)
		if assert.NoError(t, err) {
			assert.Equal(t, false, exists)
		}
	})
}

func TestRequestingMany(t *testing.T) {
	ctx := context.Background()
	collName := getARandomColl("request")
	selector := common.Selector{
		K: "meta.m1",
		V: 466,
	}
	expectedItem := TestItem{
		Meta: TestMeta{
			M1: 466,
			M2: 0,
		},
		Timestamp: time.Now(),
		Data:      rand.Int31(),
	}
	wrongItem := TestItem{
		Meta: TestMeta{
			M1: 555,
			M2: 0,
		},
		Timestamp: time.Now(),
		Data:      rand.Int31(),
	}
	replicas := 10
	t.Run("insert many items", func(t *testing.T) {
		items := replicateTestItem(expectedItem, replicas)
		err := db.Insert(ctx, collName, items)
		assert.NoError(t, err)
		// insert a wrong item
		err = db.Insert(ctx, collName, []any{&wrongItem})
	})
	t.Run("get many items", func(t *testing.T) {
		var actualItems []TestItem
		opts := common.GetOpts{
			Size: replicas,
		}
		err := db.Get(ctx, collName, selector, &actualItems, opts)
		if assert.NoError(t, err) {
			assert.Equal(t, replicas, len(actualItems))
		}
	})
}

func TestUpdating(t *testing.T) {
	ctx := context.Background()
	collName := getARandomColl("update")
	selector := common.Selector{
		K: "meta.m1",
		V: 233,
	}
	expectedItem := TestItem{
		Meta: TestMeta{
			M1: 233,
			M2: 0,
		},
		Timestamp: time.Now(),
		Data:      rand.Int31(),
	}
	t.Run("insert a test item", func(t *testing.T) {
		err := db.Insert(ctx, collName, []any{&expectedItem})
		assert.NoError(t, err)
	})
	replacedItem := expectedItem
	replacedItem.Meta.M2 = 555
	t.Run("test replacing one", func(t *testing.T) {
		err := db.ReplaceOne(ctx, collName, selector, &replacedItem)
		assert.NoError(t, err)
	})
}

func TestBSONBuilding(t *testing.T) {
	t.Run("a very simple convertion test", func(t *testing.T) {
		s := common.Selector{
			Op: common.SelectorEq,
			K:  "drink",
			V:  "coca-cola",
		}
		filter, err := ToBSONFilter(&s)
		if assert.NoError(t, err) {
			t.Logf("actual: %v", *filter)
		}
	})
	t.Run("a somewhat complicated convertion test", func(t *testing.T) {
		sA := common.Selector{
			Op: common.SelectorEq,
			K:  "drink",
			V:  "coca-cola",
		}
		sB := common.Selector{
			Op: common.SelectorEq,
			K:  "food",
			V:  "cake",
		}
		s := common.Selector{
			Op: common.SelectorOr,
			Sa: &sA,
			Sb: &sB,
		}
		filter, err := ToBSONFilter(&s)
		if assert.NoError(t, err) {
			t.Logf("actual: %v", *filter)
		}
	})
}

func getARandomColl(prefix string) string {
	return fmt.Sprintf("%s_%v", prefix, rand.Uint32())
}

type TestMeta struct {
	M1 int32 `bson:"m1"`
	M2 int32 `bson:"m2"`
}

type TestItem struct {
	Meta      TestMeta  `bson:"meta"`
	Timestamp time.Time `bson:"timestamp"`
	Data      int32     `bson:"data"`
}

// return pointers
func replicateTestItem(origItem TestItem, replicas int) []any {
	var items []any = make([]any, replicas)
	for i := 0; i < replicas; i++ {
		item := origItem
		items[i] = &item
	}
	return items
}

// return pointers
func generateTestItem() *TestItem {
	return &TestItem{
		Meta: TestMeta{
			M1: rand.Int31(),
			M2: rand.Int31(),
		},
		Timestamp: time.Now(),
		Data:      rand.Int31(),
	}
}

func generateBatchTestItems(batchSize int) []any {
	var items []any = make([]any, batchSize)
	for i := 0; i < batchSize; i++ {
		item := generateTestItem()
		items[i] = item
	}
	return items
}

func TestMain(m *testing.M) {
	var dbURI = os.Getenv("DB_URI")
	var dbName = os.Getenv("DB_NAME")
	logger, err := zaplog.NewZap(true)
	if err != nil {
		log.Fatalf("cannot init a mongodb for testing purpose: %v", err)
	}
	logger.Infof("DB_URI: %v", dbURI)
	logger.Infof("DB_NAME: %v", dbName)
	opts := MongoOpts{
		DBURI:             dbURI,
		DBName:            dbName,
		ConnectionTimeout: 5 * time.Second,
		MaxPoolSize:       10,
		Logger:            logger,
	}
	mongodb, err := NewMongo(opts)
	if err != nil {
		logger.Fatalf("cannot init a mongodb for testing purpose: %v", err)
	}

	db = mongodb
	if err := db.Ping(context.TODO()); err != nil {
		logger.Info(err)
	}
	logger.Info("connected")
	defer db.Close(context.TODO())
	os.Exit(m.Run())
}
