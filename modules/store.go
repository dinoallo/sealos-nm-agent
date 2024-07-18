package modules

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
)

type PodTrafficStore interface {
	Update(ctx context.Context, hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error
}
