package traffic_record

import (
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"
	"go.uber.org/zap"
)

type TrafficRecordStoreParam struct {
	P            *persistent.PersistentInterface
	ParentLogger *zap.SugaredLogger
}
