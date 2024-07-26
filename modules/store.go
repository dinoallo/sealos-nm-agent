package modules

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
)

type TrafficStore interface {
	UpdatePodTraffic(ctx context.Context, hash string, meta structs.PodTrafficMeta, metric structs.PodMetric) error
	UpdateHostTraffic(ctx context.Context, hash string, meta structs.HostTrafficMeta, metric structs.HostTrafficMetric) error
}
