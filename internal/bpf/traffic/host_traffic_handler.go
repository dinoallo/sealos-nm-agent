package traffic

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/host"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	"golang.org/x/sync/errgroup"
)

type HostTrafficEventHandlerConfig struct {
	WorkerCount int
}

func NewHostTrafficEventHandlerConfig() HostTrafficEventHandlerConfig {
	return HostTrafficEventHandlerConfig{
		WorkerCount: 5,
	}
}

type HostTrafficEventHandlerParams struct {
	ParentLogger log.Logger
	Events       chan *perf.Record
	HostTrafficEventHandlerConfig
	modules.ExportTrafficService
}

type HostTrafficEventHandler struct {
	logger       log.Logger
	nativeEndian binary.ByteOrder
	HostTrafficEventHandlerParams
}

func NewHostTrafficEventHandler(params HostTrafficEventHandlerParams) (*HostTrafficEventHandler, error) {
	logger, err := params.ParentLogger.WithCompName("host_traffic_event_handler")
	if err != nil {
		return nil, err
	}
	nativeEndian, err := host.GetEndian()
	if err != nil {
		return nil, err
	}
	return &HostTrafficEventHandler{
		logger:                        logger,
		nativeEndian:                  nativeEndian,
		HostTrafficEventHandlerParams: params,
	}, nil
}

func (h *HostTrafficEventHandler) Start(ctx context.Context) error {
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

func (h *HostTrafficEventHandler) handle(ctx context.Context, trafficEvents chan *perf.Record) error {
	select {
	case <-ctx.Done():
		return nil
	case trafficEvent := <-trafficEvents:
		var e host_trafficEventT
		if err := binary.Read(bytes.NewBuffer(trafficEvent.RawSample), h.nativeEndian, &e); err != nil {
			return err
		}
		if err := h.submit(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (h *HostTrafficEventHandler) submit(ctx context.Context, _event host_trafficEventT) error {
	if _event.Len <= 0 {
		return nil
	}
	// if _event.Family != unix.AF_INET && _event.Family != unix.AF_INET6 {
	// 	return nil
	// }
	event := _event.convertToRawTrafficEvent()
	if err := h.SubmitRawHostTrafficEvent(ctx, event); err != nil {
		return err
	}
	return nil
}
