package traffic

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/host"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"golang.org/x/sync/errgroup"
)

type TrafficEventHandlerParams struct {
	ParentLogger log.Logger
	Events       chan *perf.Record
	conf.TrafficEventHandlerConfig
	//TODO: add raw traffic handler
}

type TrafficEventHandler struct {
	logger       log.Logger
	nativeEndian binary.ByteOrder
	TrafficEventHandlerParams
}

func NewTrafficEventHandler(params TrafficEventHandlerParams) (*TrafficEventHandler, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_handler")
	if err != nil {
		return nil, err
	}
	nativeEndian, err := host.GetEndian()
	if err != nil {
		return nil, err
	}
	return &TrafficEventHandler{
		logger:                    logger,
		nativeEndian:              nativeEndian,
		TrafficEventHandlerParams: params,
	}, nil
}

func (h *TrafficEventHandler) Start(ctx context.Context) error {
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

func (h *TrafficEventHandler) handle(ctx context.Context, trafficEvents chan *perf.Record) error {
	select {
	case <-ctx.Done():
		return nil
	case trafficEvent := <-trafficEvents:
		var e trafficEventT
		if err := binary.Read(bytes.NewBuffer(trafficEvent.RawSample), h.nativeEndian, &e); err != nil {
			return err
		}
		if err := h.submit(ctx, &e); err != nil {
			return err
		}
	}
	return nil
}

func (h *TrafficEventHandler) submit(ctx context.Context, event *trafficEventT) error {
	//TODO: imple me
	h.logger.Info("submit")
	return nil
}
