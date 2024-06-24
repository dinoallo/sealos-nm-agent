package traffic

import (
	"context"

	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/puzpuzpuz/xsync"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/hooker"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

const (
	ingressFilterNameForHostDev = "sealos_nm_host_ingress_hook"
	egressFilterNameForHostDev  = "sealos_nm_host_egress_hook"
	ingressFilterNameForPodDev  = "sealos_nm_pod_ingress_hook"
	egressFilterNameForPodDev   = "sealos_nm_pod_egress_hook"
)

type TrafficFactoryParams struct {
	ParentLogger log.Logger
	modules.BPFTrafficFactoryConfig
	modules.ExportTrafficService
}

type TrafficFactory struct {
	log.Logger
	hostTrafficObjs     host_trafficObjects
	podTrafficObjs      pod_trafficObjects
	devHookers          *xsync.MapOf[string, *hooker.DeviceHooker] //ifaceHash -> devHooker
	trafficEventReader  *TrafficEventReader
	trafficEventHandler *TrafficEventHandler
	TrafficFactoryParams
}

func NewTrafficFactory(params TrafficFactoryParams) (*TrafficFactory, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_factory")
	if err != nil {
		return nil, modules.ErrCreatingLogger
	}
	podTrafficObjs := pod_trafficObjects{}
	if err := loadPod_trafficObjects(&podTrafficObjs, nil); err != nil {
		return nil, modules.ErrLoadingPodTrafficObjs
	}
	hostTrafficObjs := host_trafficObjects{}
	if err := loadHost_trafficObjects(&hostTrafficObjs, nil); err != nil {
		return nil, modules.ErrLoadingHostTrafficObjs
	}
	hostEgressTrafficEvents := make(chan *perf.Record)
	podIngressTrafficEvents := make(chan *perf.Record)
	handlerConfig := TrafficEventHandlerConfig{
		MaxWorker: params.HandlerMaxWorker,
	}
	handlerParams := TrafficEventHandlerParams{
		ParentLogger:              logger,
		HostEgressTrafficEvents:   hostEgressTrafficEvents,
		PodIngressTrafficEvents:   podIngressTrafficEvents,
		TrafficEventHandlerConfig: handlerConfig,
		ExportTrafficService:      params.ExportTrafficService,
	}
	handler, err := NewTrafficEventHandler(handlerParams)
	if err != nil {
		return nil, modules.ErrCreatingTrafficEventHandler
	}
	readerConfig := TrafficEventReaderConfig{
		MaxWorker:           params.ReaderMaxWorker,
		PerfEventBufferSize: (32 << 10), // 32KB
	}
	readerParams := TrafficEventReaderParams{
		ParentLogger:             logger,
		HostEgressPerfEvents:     hostTrafficObjs.EgressHostTrafficEvents,
		PodIngressPerfEvents:     podTrafficObjs.IngressPodTrafficEvents,
		HostEgressEvents:         hostEgressTrafficEvents,
		PodIngressEvents:         podIngressTrafficEvents,
		TrafficEventReaderConfig: readerConfig,
	}
	reader, err := NewTrafficEventReader(readerParams)
	if err != nil {
		return nil, modules.ErrCreatingTrafficEventReader
	}
	return &TrafficFactory{
		Logger:               logger,
		hostTrafficObjs:      hostTrafficObjs,
		podTrafficObjs:       podTrafficObjs,
		devHookers:           xsync.NewMapOf[*hooker.DeviceHooker](),
		trafficEventHandler:  handler,
		trafficEventReader:   reader,
		TrafficFactoryParams: params,
	}, nil
}

func (f *TrafficFactory) SubscribeToPodDevice(ifaceName string) error {
	newDevHooker, err := hooker.NewDeviceHooker(ifaceName, false)
	if err == hooker.ErrFailedToFindInterface {
		return modules.ErrDeviceNotFound
	} else if err != nil {
		return modules.ErrCreatingDeviceHooker
	}
	ifaceHash := getIfaceHash(ifaceName)
	devHooker, loaded := f.devHookers.LoadOrStore(ifaceHash, newDevHooker)
	if loaded {
		// this device has already been subscribed to
		return nil
	}
	if err := devHooker.AddFilterToIngressQdisc(ingressFilterNameForPodDev, f.podTrafficObjs.IngressPodTrafficHook.FD()); err != nil {
		return modules.ErrAddingIngressFilter
	}
	f.Debugf("pod device %v has been subscribed to", ifaceName)
	return nil
}

func (f *TrafficFactory) SubscribeToHostDevice(ifaceName string) error {
	newDevHooker, err := hooker.NewDeviceHooker(ifaceName, false)
	if err == hooker.ErrFailedToFindInterface {
		return modules.ErrDeviceNotFound
	} else if err != nil {
		return modules.ErrCreatingDeviceHooker
	}
	ifaceHash := getIfaceHash(ifaceName)
	devHooker, loaded := f.devHookers.LoadOrStore(ifaceHash, newDevHooker)
	if loaded {
		return nil
	}
	if err := devHooker.AddFilterToEgressQdisc(egressFilterNameForHostDev, f.hostTrafficObjs.EgressHostTrafficHook.FD()); err != nil {
		return modules.ErrAddingEgressFilter
	}
	f.Debugf("host device %v has been subscribed to", ifaceName)
	return nil
}

func (f *TrafficFactory) UnsubscribeFromPodDevice(ifaceName string) error {
	devHooker, loaded := f.devHookers.LoadAndDelete(ifaceName)
	if !loaded {
		return nil
	}
	if err := devHooker.DelFilterFromIngressQdisc(ingressFilterNameForPodDev); err != nil {
		if err == hooker.ErrFailedToFindInterface {
			return modules.ErrDeviceNotFound
		}
		return modules.ErrDeletingIngressFilter
	}
	f.Debugf("pod device %v has been unsubscribed from", ifaceName)
	return nil
}

func (f *TrafficFactory) UnsubscribeFromHostDevice(ifaceName string) error {
	devHooker, loaded := f.devHookers.LoadAndDelete(ifaceName)
	if !loaded {
		return nil
	}
	if err := devHooker.DelFilterFromEgressQdisc(egressFilterNameForHostDev); err != nil {
		if err == hooker.ErrFailedToFindInterface {
			return modules.ErrDeviceNotFound
		}
		return modules.ErrDeletingEgressFilter
	}
	f.Debugf("host device %v has been unsubscribed from", ifaceName)
	return nil
}

func (f *TrafficFactory) Start(ctx context.Context) error {
	f.trafficEventReader.Start(ctx)
	f.trafficEventHandler.Start(ctx)
	return nil
}

func getIfaceHash(ifaceName string) string {
	//TODO: imple me
	return ifaceName
}
