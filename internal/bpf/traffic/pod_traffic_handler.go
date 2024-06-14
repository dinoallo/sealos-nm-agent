package traffic

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/host"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	"golang.org/x/sync/errgroup"
)

type PodTrafficEventHandlerConfig struct {
	WorkerCount int
}

func NewPodTrafficEventHandlerConfig() PodTrafficEventHandlerConfig {
	return PodTrafficEventHandlerConfig{
		WorkerCount: 5,
	}
}

type PodTrafficEventHandlerParams struct {
	ParentLogger log.Logger
	Events       chan *perf.Record
	PodTrafficEventHandlerConfig
	modules.ExportTrafficService
}

type PodTrafficEventHandler struct {
	logger       log.Logger
	nativeEndian binary.ByteOrder
	PodTrafficEventHandlerParams
}

func NewPodTrafficEventHandler(params PodTrafficEventHandlerParams) (*PodTrafficEventHandler, error) {
	logger, err := params.ParentLogger.WithCompName("pod_traffic_event_handler")
	if err != nil {
		return nil, err
	}
	nativeEndian, err := host.GetEndian()
	if err != nil {
		return nil, err
	}
	return &PodTrafficEventHandler{
		logger:                       logger,
		nativeEndian:                 nativeEndian,
		PodTrafficEventHandlerParams: params,
	}, nil
}

func (h *PodTrafficEventHandler) Start(ctx context.Context) error {
	if h.Events == nil {
		return nil
	}
	wg := &errgroup.Group{}
	wg.SetLimit(h.WorkerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					if err := h.handle(ctx, h.Events); err != nil {
						h.logger.Error(err)
						return err
					}
					return nil
				})
			}
		}
	}()
	return nil
}

func (h *PodTrafficEventHandler) handle(ctx context.Context, trafficEvents chan *perf.Record) error {
	select {
	case <-ctx.Done():
		return nil
	case trafficEvent := <-trafficEvents:
		var e pod_trafficEventT
		if err := binary.Read(bytes.NewBuffer(trafficEvent.RawSample), h.nativeEndian, &e); err != nil {
			return err
		}
		if err := h.submit(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (h *PodTrafficEventHandler) submit(ctx context.Context, _event pod_trafficEventT) error {
	if _event.Len <= 0 {
		return nil
	}
	// if _event.Family != unix.AF_INET && _event.Family != unix.AF_INET6 {
	// 	return nil
	// }
	event := _event.convertToRawTrafficEvent()
	submitCtx, cancel := context.WithTimeout(ctx, time.Second*1) // TODO: make this configurable
	defer cancel()
	if err := h.SubmitRawPodTrafficEvent(submitCtx, event); err != nil {
		return err
	}
	return nil
}
