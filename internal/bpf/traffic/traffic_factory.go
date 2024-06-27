package traffic

import (
	"context"
	"errors"

	"github.com/cilium/ebpf"
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
	lxcTrafficObjs      lxc_trafficObjects
	cepTrafficObjs      cep_trafficObjects
	cepHookers          *xsync.MapOf[int64, *hooker.CiliumCCMHooker]
	devHookers          *xsync.MapOf[string, *hooker.DeviceHooker] //ifaceHash -> devHooker
	trafficEventReader  *TrafficEventReader
	trafficEventHandler *TrafficEventHandler
	TrafficFactoryParams
}

func NewTrafficFactory(params TrafficFactoryParams) (*TrafficFactory, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_factory")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	lxcTrafficObjs := lxc_trafficObjects{}
	if err := loadLxc_trafficObjects(&lxcTrafficObjs, nil); err != nil {
		return nil, errors.Join(err, modules.ErrLoadingLxcTrafficObjs)
	}
	hostTrafficObjs := host_trafficObjects{}
	if err := loadHost_trafficObjects(&hostTrafficObjs, nil); err != nil {
		return nil, errors.Join(err, modules.ErrLoadingHostTrafficObjs)
	}
	cepTrafficObjs := cep_trafficObjects{}
	if err := loadCep_trafficObjects(&cepTrafficObjs, nil); err != nil {
		return nil, errors.Join(err, modules.ErrLoadingCepTrafficObjs)
	}
	hostEgressTrafficEvents := make(chan *perf.Record)
	podEgressTrafficEvents := make(chan *perf.Record)
	handlerConfig := TrafficEventHandlerConfig{
		MaxWorker: params.HandlerMaxWorker,
	}
	handlerParams := TrafficEventHandlerParams{
		ParentLogger:              logger,
		HostEgressTrafficEvents:   hostEgressTrafficEvents,
		PodEgressTrafficEvents:    podEgressTrafficEvents,
		TrafficEventHandlerConfig: handlerConfig,
		ExportTrafficService:      params.ExportTrafficService,
	}
	handler, err := NewTrafficEventHandler(handlerParams)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingTrafficEventHandler)
	}
	readerConfig := TrafficEventReaderConfig{
		MaxWorker:           params.ReaderMaxWorker,
		PerfEventBufferSize: (32 << 10), // 32KB
	}
	var egressPodTrafficPerfEvents *ebpf.Map
	if params.UseCiliumCCM {
		egressPodTrafficPerfEvents = cepTrafficObjs.EgressCepTrafficEvents
	}
	readerParams := TrafficEventReaderParams{
		ParentLogger:             logger,
		HostEgressPerfEvents:     hostTrafficObjs.EgressHostTrafficEvents,
		PodEgressPerfEvents:      egressPodTrafficPerfEvents,
		HostEgressEvents:         hostEgressTrafficEvents,
		PodEgressEvents:          podEgressTrafficEvents,
		TrafficEventReaderConfig: readerConfig,
	}
	reader, err := NewTrafficEventReader(readerParams)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingTrafficEventReader)
	}
	return &TrafficFactory{
		Logger:               logger,
		hostTrafficObjs:      hostTrafficObjs,
		lxcTrafficObjs:       lxcTrafficObjs,
		cepTrafficObjs:       cepTrafficObjs,
		devHookers:           xsync.NewMapOf[*hooker.DeviceHooker](),
		cepHookers:           xsync.NewIntegerMapOf[int64, *hooker.CiliumCCMHooker](),
		trafficEventHandler:  handler,
		trafficEventReader:   reader,
		TrafficFactoryParams: params,
	}, nil
}

func (f *TrafficFactory) SubscribeToPodDevice(ifaceName string) error {
	newDevHooker, err := hooker.NewDeviceHooker(ifaceName, false)
	if errors.Is(err, hooker.ErrInterfaceNotExists) {
		return errors.Join(err, modules.ErrDeviceNotFound)
	} else if err != nil {
		return errors.Join(err, modules.ErrCreatingDeviceHooker)
	}
	ifaceHash := getIfaceHash(ifaceName)
	devHooker, loaded := f.devHookers.LoadOrStore(ifaceHash, newDevHooker)
	if loaded {
		// this device has already been subscribed to
		return nil
	}
	// attach to filter to ingress qdisc of a lxc device so that we can get egress traffic of a pod
	// notice that this is not a bug since the ingress side of lxc device equals to the egress side of a pod (they are a veth pair)
	if err := devHooker.AddFilterToIngressQdisc(ingressFilterNameForPodDev, f.lxcTrafficObjs.IngressLxcTrafficHook.FD()); err != nil {
		return errors.Join(err, modules.ErrAddingIngressFilter)
	}
	f.Debugf("pod device %v has been subscribed to", ifaceName)
	return nil
}

func (f *TrafficFactory) SubscribeToHostDevice(ifaceName string) error {
	newDevHooker, err := hooker.NewDeviceHooker(ifaceName, false)
	if errors.Is(err, hooker.ErrInterfaceNotExists) {
		return errors.Join(err, modules.ErrDeviceNotFound)
	} else if err != nil {
		return errors.Join(err, modules.ErrCreatingDeviceHooker)
	}
	ifaceHash := getIfaceHash(ifaceName)
	devHooker, loaded := f.devHookers.LoadOrStore(ifaceHash, newDevHooker)
	if loaded {
		return nil
	}
	if err := devHooker.AddFilterToEgressQdisc(egressFilterNameForHostDev, f.hostTrafficObjs.EgressHostTrafficHook.FD()); err != nil {
		return errors.Join(err, modules.ErrAddingEgressFilter)
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
		if errors.Is(err, hooker.ErrInterfaceNotExists) {
			return nil
		}
		return errors.Join(err, modules.ErrDeletingIngressFilter)
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
		if errors.Is(err, hooker.ErrInterfaceNotExists) {
			return nil
		}
		return errors.Join(err, modules.ErrDeletingEgressFilter)
	}
	f.Debugf("host device %v has been unsubscribed from", ifaceName)
	return nil
}

func (f *TrafficFactory) SubscribeToCep(eid int64) error {
	newCepHooker := hooker.NewCiliumCCMHooker(eid)
	cepHooker, loaded := f.cepHookers.LoadOrStore(eid, newCepHooker)
	if loaded {
		return nil
	}
	if err := cepHooker.AttachV4EgressHook(f.cepTrafficObjs.EgressCepTrafficHook); err != nil {
		if errors.Is(err, hooker.ErrCiliumCCMNotExists) {
			return errors.Join(err, modules.ErrCepNotFound)
		}
		return errors.Join(err, modules.ErrAttachingEgressHookToCCM)
	}
	f.Debugf("cep %v has been subscribed to", eid)
	return nil
}

func (f *TrafficFactory) UnsubscribeFromCep(eid int64) error {
	cepHooker, loaded := f.cepHookers.LoadAndDelete(eid)
	if !loaded {
		return nil
	}
	if err := cepHooker.DetachAllHooks(); err != nil {
		if errors.Is(err, hooker.ErrCiliumCCMNotExists) {
			return nil
		}
		return errors.Join(err, modules.ErrDetachingAllHooksFromCCM)
	}
	f.Debugf("cep %v has been unsubscribed from", eid)
	return nil
}

func (f *TrafficFactory) Start(ctx context.Context) error {
	f.trafficEventReader.Start(ctx)
	f.trafficEventHandler.Start(ctx)
	return nil
}

func (f *TrafficFactory) Close() {
	delFilter := func(ifaceName string, devHooker *hooker.DeviceHooker) bool {
		if err := devHooker.Close(); err != nil {
			f.Error(err)
		}
		return true
	}
	f.devHookers.Range(delFilter)
	detachHook := func(eid int64, cepHooker *hooker.CiliumCCMHooker) bool {
		if err := cepHooker.DetachAllHooks(); err != nil {
			f.Error(err)
		}
		return true
	}
	f.cepHookers.Range(detachHook)
	f.lxcTrafficObjs.Close()
	f.hostTrafficObjs.Close()
	f.cepTrafficObjs.Close()
}

func getIfaceHash(ifaceName string) string {
	//TODO: imple me
	return ifaceName
}
