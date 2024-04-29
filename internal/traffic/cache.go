// this file imples cache.Convertable interface
package traffic

import (
	"fmt"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
)

func (e *rawTrafficMetricEntry) ConvertToData() []*structs.RawTraffic {
	var items []*structs.RawTraffic
	convertToData := func(key, value any) bool {
		tag, ok := key.(string)
		if !ok {
			return true
		}
		metric, ok := value.(*rawTrafficMetric)
		if !ok {
			return true
		}
		now := time.Now()
		item := &structs.RawTraffic{
			Meta: structs.RawTrafficMetaData{
				IP:   e.meta.ip,
				Tag:  tag,
				Node: e.meta.node,
			},
			Metric: structs.RawTrafficMetric{
				SentBytes: metric.sentBytes.Load(),
				RecvBytes: metric.recvBytes.Load(),
			},
			ID:        getID(e.meta, tag, now),
			Timestamp: now,
		}
		items = append(items, item)
		return true
	}
	e.metrics.Range(convertToData)
	return items
}

func (e *rawTrafficMetricEntry) GetHash() string {
	return e.hash
}

func (e *rawTrafficMetricEntry) Load(tag string) (*rawTrafficMetric, error) {
	var metric *rawTrafficMetric
	newMetric := newRawTrafficMetric()
	metricKey := tag
	_metric, loaded := e.metrics.LoadOrStore(metricKey, newMetric)
	if !loaded {
		metric = newMetric
	} else {
		var ok bool
		metric, ok = _metric.(*rawTrafficMetric)
		if !ok {
			return nil, fmt.Errorf("not a metric???")
		}
	}
	return metric, nil
}
