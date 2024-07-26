package traffic

import (
	"context"
	"errors"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
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
	Host         string
	ParentLogger log.Logger
	conf.BPFTrafficFactoryConfig
	modules.TrafficStore
	modules.Classifier
}

type TrafficFactory struct {
	log.Logger
	trafficObjs         trafficObjects
	cepHookers          *xsync.MapOf[int64, *hooker.CiliumCCMHooker]
	hostDevHookers      *xsync.MapOf[string, *hooker.DeviceHooker]
	trafficEventReader  *TrafficEventReader
	trafficEventHandler *TrafficEventHandler
	TrafficFactoryParams
}

func NewTrafficFactory(params TrafficFactoryParams) (*TrafficFactory, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_factory")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	trafficObjs := trafficObjects{}
	if err := loadTrafficObjects(&trafficObjs, nil); err != nil {
		return nil, errors.Join(err, modules.ErrLoadingCepTrafficObjs)
	}
	egressPodTrafficRecords := make(chan *ringbuf.Record)
	egressPodNotiRecords := make(chan *ringbuf.Record)
	egressHostTrafficRecords := make(chan *ringbuf.Record)
	egressHostNotiRecords := make(chan *ringbuf.Record)
	handlerConfig := TrafficEventHandlerConfig{
		MaxWorker:           params.HandlerMaxWorker,
		HostTrafficDumpMode: params.HostDumpMode,
		PodTrafficDumpMode:  params.PodDumpMode,
	}
	handlerParams := TrafficEventHandlerParams{
		Host:                      params.Host,
		ParentLogger:              logger,
		EgressPodTrafficRecords:   egressPodTrafficRecords,
		EgressPodNotiRecords:      egressPodNotiRecords,
		EgressHostTrafficRecords:  egressHostTrafficRecords,
		EgressHostNotiRecords:     egressHostNotiRecords,
		TrafficEventHandlerConfig: handlerConfig,
		TrafficStore:              params.TrafficStore,
		Classifier:                params.Classifier,
	}
	handler, err := NewTrafficEventHandler(handlerParams)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingTrafficEventHandler)
	}
	readerConfig := TrafficEventReaderConfig{
		MaxWorker:      params.ReaderMaxWorker,
		ReadingTimeout: 1 * time.Second, // TODO: make this configurable
	}
	readerParams := TrafficEventReaderParams{
		ParentLogger:             logger,
		TrafficObjs:              &trafficObjs,
		EgressPodTrafficRecords:  egressPodTrafficRecords,
		EgressPodNotiRecords:     egressPodNotiRecords,
		EgressHostTrafficRecords: egressHostTrafficRecords,
		EgressHostNotiRecords:    egressHostNotiRecords,
		TrafficEventReaderConfig: readerConfig,
	}
	reader, err := NewTrafficEventReader(readerParams)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingTrafficEventReader)
	}
	return &TrafficFactory{
		Logger:               logger,
		trafficObjs:          trafficObjs,
		cepHookers:           xsync.NewIntegerMapOf[int64, *hooker.CiliumCCMHooker](),
		hostDevHookers:       xsync.NewMapOf[*hooker.DeviceHooker](),
		trafficEventHandler:  handler,
		trafficEventReader:   reader,
		TrafficFactoryParams: params,
	}, nil
}

func (f *TrafficFactory) SubscribeToCep(eid int64) error {
	newCepHooker := hooker.NewCiliumCCMHooker(eid)
	cepHooker, _ := f.cepHookers.LoadOrStore(eid, newCepHooker)
	if err := cepHooker.AttachV4EgressHook(f.trafficObjs.EgressCepTrafficHook); err != nil {
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
	if err := f.detachAllHooks(cepHooker); err != nil && !errors.Is(err, hooker.ErrCiliumCCMNotExists) {
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

func (f *TrafficFactory) SubscribeToHostDev(iface string) error {
	newDevHooker, err := hooker.NewDeviceHooker(iface, false)
	if err != nil {
		return err
	}
	devHooker, _ := f.hostDevHookers.LoadOrStore(iface, newDevHooker)
	hookFD := f.trafficObjs.EgressHostTrafficHook.FD()
	if err := devHooker.AddFilterToEgressQdisc(egressFilterNameForHostDev, hookFD); err != nil {
		return err
	}
	f.Debugf("host device: %v has been subscribed to", iface)
	return nil
}

func (f *TrafficFactory) UnsubscribeFromHostDev(iface string) error {
	devHooker, loaded := f.hostDevHookers.LoadAndDelete(iface)
	if !loaded {
		return nil
	}
	if err := devHooker.Close(); err != nil {
		return err
	}
	f.Debugf("hostdev %v has been unsubscribed from", iface)
	return nil
}

func (f *TrafficFactory) Close() {
	detachCepHook := func(eid int64, cepHooker *hooker.CiliumCCMHooker) bool {
		if err := f.detachAllHooks(cepHooker); err != nil {
			f.Error(err)
		}
		return true
	}
	detachDevHook := func(devName string, devHooker *hooker.DeviceHooker) bool {
		if err := devHooker.Close(); err != nil {
			f.Error(err)
		}
		return true
	}
	f.cepHookers.Range(detachCepHook)
	f.hostDevHookers.Range(detachDevHook)
	f.trafficObjs.Close()
}

func (f *TrafficFactory) detachAllHooks(cepHooker *hooker.CiliumCCMHooker) error {
	var err error
	err = cepHooker.DetachV4EgressHook()
	return err
}

func getIfaceHash(ifaceName string) string {
	//TODO: imple me
	return ifaceName
}
