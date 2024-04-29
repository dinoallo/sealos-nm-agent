package traffic

import (
	"sync"
	"sync/atomic"
	"time"
)

// TODO: add tcp total, udp total, etc...
type rawTrafficMetric struct {
	sentBytes atomic.Uint32
	recvBytes atomic.Uint32
}

func newRawTrafficMetric() *rawTrafficMetric {
	return &rawTrafficMetric{
		sentBytes: atomic.Uint32{},
		recvBytes: atomic.Uint32{},
	}
}

type rawTrafficMetricEntryMeta struct {
	ip   string
	node string
}

type rawTrafficMetricEntry struct {
	hash    string
	meta    rawTrafficMetricEntryMeta
	metrics *sync.Map // store the metrics indexed by the port number
}

func newRawTrafficMetricEntry() *rawTrafficMetricEntry {
	return &rawTrafficMetricEntry{
		metrics: &sync.Map{},
	}
}

func getID(meta rawTrafficMetricEntryMeta, tag string, timestamp time.Time) string {
	//TODO: imple me
	return meta.ip
}
