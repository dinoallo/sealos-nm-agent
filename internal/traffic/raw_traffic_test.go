package traffic

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/common"
	zaplog "github.com/dinoallo/sealos-networkmanager-agent/pkg/log/zap"
	"github.com/stretchr/testify/assert"
)

var (
	testingDB *mock.TestingDB
	h         *RawTrafficHandler
	//	defaultTimeout time.Duration = 1 * time.Second
	defaultCacheTTL = 1 * time.Second
	summaryCacheTTL = 10 * time.Second
	defaultColl     = "default_coll"
	summaryColl     = "summary_coll"
)

func TestAccepting(t *testing.T) {
	ctx := context.Background()
	var events []structs.RawTrafficEvent
	var size int = 5
	t.Run("generate some events", func(t *testing.T) {
		for i := 0; i < size; i++ {
			event := generateRawTrafficEvent()
			events = append(events, event)
		}
	})
	t.Run("accept raw traffic events and wait for a while", func(t *testing.T) {
		for _, event := range events {
			err := h.AcceptRawTrafficEvent(ctx, event)
			assert.NoError(t, err)
		}
	})
	t.Run("wait a while and dump traffic data from the default cache", func(t *testing.T) {
		time.Sleep(defaultCacheTTL*time.Duration(size) + time.Second*1)
		objs := &[]any{}
		err := testingDB.Get(ctx, defaultColl, common.Selector{}, objs, common.GetOpts{})
		if assert.NoError(t, err) {
			assert.Equal(t, len(events)*2, len(*objs))
		}
	})
	//TODO: add test for summary cache
}

// TODO: move these function to an util lib like pkg random
func generateIPV4() string {
	buf := make([]byte, 4)
	_ip := rand.Uint32()
	binary.LittleEndian.PutUint32(buf, _ip)
	ip := net.IP(buf)
	return ip.String()
}

func generatePort() uint32 {
	return uint32(rand.Int31n(65536))
}

func generateID() string {
	return fmt.Sprintf("%v", rand.Int31()) //TODO: make me a random string
}

func generateRawTrafficEvent() structs.RawTrafficEvent {
	return structs.RawTrafficEvent{
		RawTrafficEventMeta: structs.RawTrafficEventMetaData{
			SrcIP:   generateIPV4(),
			SrcPort: generatePort(),
			DstIP:   generateIPV4(),
			DstPort: generatePort(),
			Family:  6,
		},
		ID:        generateID(), //TODO: make me a random string
		DataBytes: 333,
		Timestamp: time.Now(),
	}
}

func TestMain(m *testing.M) {
	logger, err := zaplog.NewZap(true)
	if err != nil {
		log.Printf("failed to initialize the logger: %v", err)
		return
	}
	config := NewRawTrafficHandlerConfig()
	config.DefaultColl = defaultColl
	config.SummaryColl = summaryColl
	config.GetBatchTimeout = 5 * time.Second
	config.DefaultCacheConfig.EntryTTL = defaultCacheTTL
	config.SummaryCacheConfig.EntryTTL = summaryCacheTTL
	dbConfig := mock.TestingDBConfig{
		MaxItems: 100,
	}
	testingDB = mock.NewTestingDB(dbConfig)
	params := RawTrafficHandlerParams{
		DB:                      testingDB,
		ParentLogger:            logger,
		RawTrafficHandlerConfig: config,
	}
	_h, err := NewRawTrafficHandler(params)
	if err != nil {
		logger.Error(err)
		return
	}
	h = _h
	if err := h.Start(context.Background()); err != nil {
		logger.Error(err)
		return
	}
	m.Run()
}
