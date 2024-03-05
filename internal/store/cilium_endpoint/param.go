package cilium_endpoint

import (
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/persistent"
	"go.uber.org/zap"
)

type CiliumEndpointStoreParam struct {
	P            *persistent.PersistentInterface
	ParentLogger *zap.SugaredLogger
}
