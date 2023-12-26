package bytecount

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/store"
)

func (bf *Factory) AddExportChannel(ctx context.Context, ec chan *store.TrafficReport) {
	log := bf.logger
	if ec == nil {
		log.Info("nil export channel added. is this correct?")
		return
	}
	bf.bytecountExportChannel = ec
}

func (bf *Factory) CleanUp(ctx context.Context, ipAddr string) error {
	return bf.store.DeleteTrafficAccount(ctx, ipAddr)
}
