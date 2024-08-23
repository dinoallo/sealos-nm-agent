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
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/host"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	taglib "github.com/dinoallo/sealos-networkmanager-agent/pkg/tag"
	"golang.org/x/sync/errgroup"
)

const (
	defaultSubmitTimeout = time.Second * 1
)

type TrafficEventHandlerConfig struct {
	PodTrafficDumpMode  bool
	HostTrafficDumpMode bool
	MaxWorker           int
}

type TrafficEventHandlerParams struct {
	Host                     string
	ParentLogger             log.Logger
	EgressPodTrafficRecords  chan *ringbuf.Record
	EgressPodNotiRecords     chan *ringbuf.Record
	EgressHostTrafficRecords chan *ringbuf.Record
	EgressHostNotiRecords    chan *ringbuf.Record
	TrafficEventHandlerConfig
	modules.TrafficStore
	modules.Classifier
}

type TrafficEventHandler struct {
	log.Logger
	nativeEndian          binary.ByteOrder
	hostEgressItemsToDump chan structsapi.RawTraffic
	podEgressItemsToDump  chan structsapi.RawTraffic
	TrafficEventHandlerParams
}

func (h *TrafficEventHandler) Start(ctx context.Context) {
	if h.PodTrafficDumpMode {
		h.doHandling(ctx, h.MaxWorker, h.dumpPodEgress)
	}
	if h.HostTrafficDumpMode {
		h.doHandling(ctx, h.MaxWorker, h.dumpHostEgress)
	}
	h.doHandling(ctx, h.MaxWorker, h.handlePodEgress)
	h.doHandling(ctx, h.MaxWorker, h.handlePodEgressNotis)
	h.doHandling(ctx, h.MaxWorker, h.handleHostEgress)
	h.doHandling(ctx, h.MaxWorker, h.handleHostEgressNotis)
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
		hostEgressItemsToDump:     make(chan structsapi.RawTraffic),
		podEgressItemsToDump:      make(chan structsapi.RawTraffic),
		TrafficEventHandlerParams: params,
	}, nil
}

func (h *TrafficEventHandler) handlePodEgress(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.EgressPodTrafficRecords:
		var e trafficEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &e); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if e.Len <= 0 {
			return nil
		}
		item := e.convertToRawTraffic()
		if h.PodTrafficDumpMode {
			go func() {
				h.podEgressItemsToDump <- item
			}()
		}
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

func (h *TrafficEventHandler) handlePodEgressNotis(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.EgressPodNotiRecords:
		var notification notificationT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &notification); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if notification.Error == uint32(1) {
			h.Error("failed to reserve space for %v since the bpf ringbuffer is full. maybe you need to increase the buffer size", "pod egress")
		}
	}
	return nil
}

func (h *TrafficEventHandler) handleHostEgressNotis(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.EgressHostNotiRecords:
		var notification notificationT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &notification); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if notification.Error == uint32(1) {
			h.Error("failed to reserve space for %v since the bpf ringbuffer is full. maybe you need to increase the buffer size", "host egress")
		}
	}
	return nil
}

func (h *TrafficEventHandler) handleHostEgress(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case record := <-h.EgressHostTrafficRecords:
		var e trafficEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), h.nativeEndian, &e); err != nil {
			return errors.Join(err, modules.ErrReadingFromRawSample)
		}
		if e.Len <= 0 {
			return nil
		}
		item := e.convertToRawTraffic()
		if h.HostTrafficDumpMode {
			go func() {
				h.hostEgressItemsToDump <- item
			}()
		}
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
		// if this traffic isn't destinated to the world, ignore it
		if dstAddrType != modules.AddrTypeWorld {
			return nil
		}
		if err := h.handleOutboundTrafficFromHost(ctx, item.Meta.Src, &item); err != nil {
			return err
		}
	}
	return nil
}

// `dumpHostEgress` is only useful when the dump mode is on
func (h *TrafficEventHandler) dumpHostEgress(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case item := <-h.hostEgressItemsToDump:
		srcType, err := h.GetAddrType(item.Meta.Src.IP)
		if err != nil {
			return err
		}
		dstType, err := h.GetAddrType(item.Meta.Dst.IP)
		if err != nil {
			return err
		}
		h.Infof("host egress; src %v:%v type %v => dst %v:%v type %v;Tx %v bytes", item.Meta.Src.IP, item.Meta.Src.Port, srcType, item.Meta.Dst.IP, item.Meta.Dst.Port, dstType, item.DataBytes)
		return nil
	}
}

// `dumpPodEgress` is only useful when the dump mode is on
func (h *TrafficEventHandler) dumpPodEgress(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case item := <-h.podEgressItemsToDump:
		srcType, err := h.GetAddrType(item.Meta.Src.IP)
		if err != nil {
			return err
		}
		dstType, err := h.GetAddrType(item.Meta.Dst.IP)
		if err != nil {
			return err
		}
		h.Infof("pod egress; src %v:%v type %v => dst %v:%v type %v;Tx %v bytes", item.Meta.Src.IP, item.Meta.Src.Port, srcType, item.Meta.Dst.IP, item.Meta.Dst.Port, dstType, item.DataBytes)
		return nil
	}
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
	// check if the outbound traffic from node ports
	isFromNodePort, err := h.IsPortNodePort(podAddr, podPort)
	if err != nil {
		return err
	}
	if (isFromExposedPort || isFromNodePort) && dstAddrType != modules.AddrTypePod {
		tag := taglib.GetTagSrcPortN(podPort)
		if err := h.updatePodMetric(ctx, podAddr, *tag, podMeta, podMetric); err != nil {
			return err
		}
	}
	return nil
}

func (h *TrafficEventHandler) handleOutboundTrafficFromHost(ctx context.Context, addrInfo structsapi.RawTrafficAddrInfo, item *structsapi.RawTraffic) error {
	remoteIP := item.Meta.Dst.IP
	hostMetric := structsapi.HostTrafficMetric{
		SentBytes: uint64(item.DataBytes),
		RecvBytes: 0,
	}
	hostMeta := structsapi.HostTrafficMeta{
		RemoteIP: item.Meta.Dst.IP,
		Node:     h.Host,
	}
	if err := h.updateHostMetric(ctx, remoteIP, hostMeta, hostMetric); err != nil {
		return err
	}
	return nil
}

func (h *TrafficEventHandler) updatePodMetric(ctx context.Context, podAddr string, tag taglib.Tag, podMeta structsapi.PodMeta, podMetric structsapi.PodMetric) error {
	podTrafficMeta := h.getPodTrafficMeta(podAddr, tag, podMeta)
	hash := getPodMetaHash(podAddr, tag)
	if err := h.TrafficStore.UpdatePodTraffic(ctx, hash, podTrafficMeta, podMetric); err != nil {
		return err
	}
	return nil
}

func (h *TrafficEventHandler) updateHostMetric(ctx context.Context, remoteIP string, hostMeta structsapi.HostTrafficMeta, hostMetric structsapi.HostTrafficMetric) error {
	hash := getHostMetaHash(remoteIP)
	if err := h.TrafficStore.UpdateHostTraffic(ctx, hash, hostMeta, hostMetric); err != nil {
		return err
	}
	return nil
}
func getPodMetaHash(podAddr string, tag taglib.Tag) string {
	return fmt.Sprintf("%s/%s", podAddr, tag.String)
}

func getHostMetaHash(remoteIP string) string {
	return remoteIP
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
