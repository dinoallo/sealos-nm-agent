package traffic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/host"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	"golang.org/x/sync/errgroup"
)

const (
	defaultSubmitTimeout = time.Second * 1
)

type TrafficEventHandlerConfig struct {
	MaxWorker int
}

type TrafficEventHandlerParams struct {
	ParentLogger            log.Logger
	HostEgressTrafficEvents chan *perf.Record
	PodIngressTrafficEvents chan *perf.Record
	TrafficEventHandlerConfig
	modules.ExportTrafficService
}

type TrafficEventHandler struct {
	log.Logger
	nativeEndian binary.ByteOrder
	TrafficEventHandlerParams
}

func (h *TrafficEventHandler) Start(ctx context.Context) {
	doHandling(ctx, h.MaxWorker, h.handleHostEgress, h.Logger)
	doHandling(ctx, h.MaxWorker, h.handlePodIngress, h.Logger)
}

func NewTrafficEventHandler(params TrafficEventHandlerParams) (*TrafficEventHandler, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_handler")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	nativeEndian, err := host.GetEndian()
	if err != nil {
		return nil, errors.Join(err, modules.ErrGettingHostEndian)
	}
	return &TrafficEventHandler{
		Logger:                    logger,
		nativeEndian:              nativeEndian,
		TrafficEventHandlerParams: params,
	}, nil
}

func (h *TrafficEventHandler) handleHostEgress(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.HostEgressTrafficEvents:
		var e host_trafficEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &e); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if e.Len <= 0 {
			// If this traffic event doesn't have any data, do not submit anything
			return nil
		}
		event := e.convertToRawTrafficEvent()
		return submitWithTimeout(ctx, event, defaultSubmitTimeout, h.SubmitRawHostTrafficEvent)
	}
}

func (h *TrafficEventHandler) handlePodIngress(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.PodIngressTrafficEvents:
		var e pod_trafficEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &e); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if e.Len <= 0 {
			// If this traffic event doesn't have any data, do not submit anything
			return nil
		}
		event := e.convertToRawTrafficEvent()
		return submitWithTimeout(ctx, event, defaultSubmitTimeout, h.SubmitRawPodTrafficEvent)
	}
}

func submitWithTimeout(ctx context.Context, event structs.RawTrafficEvent, timeout time.Duration, submitFunc func(context.Context, structs.RawTrafficEvent) error) error {
	submitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := submitFunc(submitCtx, event); err != nil {
		return err
	}
	return nil
}

func doHandling(ctx context.Context, workerCount int, handleFunc func(context.Context) error, logger log.Logger) {
	wg := &errgroup.Group{}
	wg.SetLimit(workerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					if err := handleFunc(ctx); err != nil {
						logger.Error("failed to handle: %v", err)
						return err
					}
					return nil
				})
			}
		}
	}()
}
