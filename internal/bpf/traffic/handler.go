package traffic

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/host"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	netutil "github.com/dinoallo/sealos-networkmanager-agent/pkg/net/util"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type TrafficEventHandlerConfig struct {
	WorkerCount int
}

func NewTrafficEventHandlerConfig() TrafficEventHandlerConfig {
	return TrafficEventHandlerConfig{
		WorkerCount: 5,
	}
}

type TrafficEventHandlerParams struct {
	ParentLogger log.Logger
	Events       chan *perf.Record
	TrafficEventHandlerConfig
	modules.RawTrafficStore
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
		if err := h.submit(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (h *TrafficEventHandler) submit(ctx context.Context, _event trafficEventT) error {
	//TODO: imple me
	if _event.Len <= 0 {
		return nil
	}
	//TODO: skip self
	event := convertToRawTrafficEvent(_event)
	if err := h.AcceptRawTrafficEvent(ctx, event); err != nil {
		return err
	}
	return nil
}

func convertToRawTrafficEvent(_event trafficEventT) structs.RawTrafficEvent {
	//TODO: check ipv6
	e := structs.RawTrafficEvent{
		RawTrafficEventMeta: structs.RawTrafficEventMetaData{
			Protocol: _event.Protocol,
			Family:   _event.Family,
			// Identity: identity.NumericIdentity(_event.Identity),
		},
		// ID:        id, //TODO: generate id
		DataBytes: _event.Len,
		Timestamp: time.Now(), //TODO: maybe use bpf timestamp?
	}
	// handle ipv4 and ipv6
	var srcIP string
	var dstIP string
	if _event.Family == unix.AF_INET {
		if _srcIP, ok := netutil.ToIP(_event.SrcIp4, nil, 4); ok {
			srcIP = _srcIP.String()
		}
		if _dstIP, ok := netutil.ToIP(_event.DstIp4, nil, 4); ok {
			dstIP = _dstIP.String()
		}
	} else if _event.Family == unix.AF_INET6 {
		if _srcIP, ok := netutil.ToIP(0, _event.SrcIp6[:], 6); ok {
			srcIP = _srcIP.String()
		}
		if _dstIP, ok := netutil.ToIP(0, _event.SrcIp6[:], 6); ok {
			dstIP = _dstIP.String()
		}
	} else {
		return e
	}
	e.RawTrafficEventMeta.SrcIP = srcIP
	e.RawTrafficEventMeta.DstIP = dstIP
	e.RawTrafficEventMeta.SrcPort = _event.SrcPort
	e.RawTrafficEventMeta.DstPort = uint32(_event.DstPort)
	return e
}
