package traffic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	structsapi "github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/host"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	taglib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/tag"
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
	PodEgressTrafficRecords chan *ringbuf.Record
	EgressErrorRecords      chan *ringbuf.Record
	TrafficEventHandlerConfig
	modules.PodTrafficStore
	modules.Classifier
}

type TrafficEventHandler struct {
	log.Logger
	nativeEndian binary.ByteOrder
	TrafficEventHandlerParams
}

func (h *TrafficEventHandler) Start(ctx context.Context) {
	h.doHandling(ctx, h.MaxWorker, h.handlePodEgress)
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

func (h *TrafficEventHandler) handlePodEgress(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.PodEgressTrafficRecords:
		var e trafficEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &e); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if e.Len <= 0 {
			return nil
		}
		item := e.convertToRawTraffic()
		srcAddr := item.Meta.Src.IP
		dstAddr := item.Meta.Dst.IP
		srcAddrType, err := h.GetAddrType(srcAddr)
		if err != nil {
			return err
		}
		dstAddrType, err := h.GetAddrType(dstAddr)
		if err != nil {
			return err
		}
		if checkSkipped(srcAddrType, dstAddrType) {
			return nil
		}
		if srcAddrType == modules.AddrTypePod {
			if err := h.handleOutboundTrafficFromPod(ctx, item.Meta.Src, dstAddrType, &item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *TrafficEventHandler) handleEgressErrors(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.EgressErrorRecords:
		var notification notificationT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &notification); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if notification.Error == uint32(1) {
			h.Error("failed to reserve space for egress traffic since the bpf ringbuffer is full. maybe you need to increase the buffer size")
		}
	}
	return nil
}

func (h *TrafficEventHandler) handleOutboundTrafficFromPod(ctx context.Context, addrInfo structsapi.RawTrafficAddrInfo, dstAddrType modules.AddrType, item *structsapi.RawTraffic) error {
	podAddr := addrInfo.IP
	podPort := addrInfo.Port
	podMeta, exists := h.GetPodMeta(podAddr)
	if !exists {
		//TODO: handle me
		return nil
	}
	podMetric := structsapi.PodMetric{
		SentBytes: uint64(item.DataBytes),
		RecvBytes: 0,
	}
	// check if the outbound traffic is sent to world
	if dstAddrType == modules.AddrTypeWorld {
		tag := taglib.TagDstWorld
		if err := h.updatePodMetric(ctx, podAddr, tag, podMeta, podMetric); err != nil {
			return err
		}
		return nil
	}
	// check if the outbound traffic from exposed ports
	isFromExposedPort, err := h.IsPortExposed(podAddr, podPort)
	if err != nil {
		return err
	}
	if isFromExposedPort && dstAddrType != modules.AddrTypePod {
		tag := taglib.GetTagSrcPortN(podPort)
		if err := h.updatePodMetric(ctx, podAddr, *tag, podMeta, podMetric); err != nil {
			return err
		}
	}
	return nil
}

func submitWithTimeout(ctx context.Context, event structs.RawTrafficEvent, timeout time.Duration, submitFunc func(context.Context, structs.RawTrafficEvent) error) error {
	submitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := submitFunc(submitCtx, event); err != nil {
		return err
	}
	return nil
}

func (h *TrafficEventHandler) updatePodMetric(ctx context.Context, podAddr string, tag taglib.Tag, podMeta structsapi.PodMeta, podMetric structsapi.PodMetric) error {
	podTrafficMeta := h.getPodTrafficMeta(podAddr, tag, podMeta)
	hash := getPodMetaHash(podAddr, tag)
	if err := h.PodTrafficStore.Update(ctx, hash, podTrafficMeta, podMetric); err != nil {
		return err
	}
	return nil
}

func getPodMetaHash(podAddr string, tag taglib.Tag) string {
	return fmt.Sprintf("%s/%s", podAddr, tag.String)
}

func (h *TrafficEventHandler) getPodTrafficMeta(addr string, tag taglib.Tag, _meta structsapi.PodMeta) structsapi.PodTrafficMeta {
	return structsapi.PodTrafficMeta{
		PodName:      _meta.Name,
		PodNamespace: _meta.Namespace,
		PodAddress:   addr,
		TrafficTag:   tag.String,
		PodType:      _meta.Type,
		PodTypeName:  _meta.TypeName,
		Node:         _meta.Node,
	}
}

func (h *TrafficEventHandler) doHandling(ctx context.Context, workerCount int, handleFunc func(context.Context) error) {
	eg := errgroup.Group{}
	for i := 0; i < workerCount; i++ {
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				default:
					if err := handleFunc(ctx); err != nil {
						h.Errorf("failed to handle: %v", err)
						continue
					}
				}
			}
		})
	}
}

func checkSkipped(srcAddrType modules.AddrType, dstAddrType modules.AddrType) bool {
	return srcAddrType == modules.AddrTypeSkipped || srcAddrType == modules.AddrTypeUnknown || dstAddrType == modules.AddrTypeSkipped || dstAddrType == modules.AddrTypeUnknown
}
