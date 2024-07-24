package traffic

import (
	"context"
	"errors"
	"time"

	"github.com/cilium/ebpf"
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
	ParentLogger log.Logger
	conf.BPFTrafficFactoryConfig
	modules.PodTrafficStore
	modules.Classifier
}

type TrafficFactory struct {
	log.Logger
	cepTrafficObjs      cep_trafficObjects
	cepHookers          *xsync.MapOf[int64, *hooker.CiliumCCMHooker]
	trafficEventReader  *TrafficEventReader
	trafficEventHandler *TrafficEventHandler
	TrafficFactoryParams
}

func NewTrafficFactory(params TrafficFactoryParams) (*TrafficFactory, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_factory")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	cepTrafficObjs := cep_trafficObjects{}
	if err := loadCep_trafficObjects(&cepTrafficObjs, nil); err != nil {
		return nil, errors.Join(err, modules.ErrLoadingCepTrafficObjs)
	}
	podEgressTrafficRecords := make(chan *ringbuf.Record)
	egressErrorRecords := make(chan *ringbuf.Record)
	handlerConfig := TrafficEventHandlerConfig{
		MaxWorker: params.HandlerMaxWorker,
	}
	handlerParams := TrafficEventHandlerParams{
		ParentLogger:              logger,
		PodEgressTrafficRecords:   podEgressTrafficRecords,
		EgressErrorRecords:        egressErrorRecords,
		TrafficEventHandlerConfig: handlerConfig,
		PodTrafficStore:           params.PodTrafficStore,
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
	var podEgressTrafficEvents *ebpf.Map
	var egressErrors *ebpf.Map
	podEgressTrafficEvents = cepTrafficObjs.EgressCepTrafficEvents
	egressErrors = cepTrafficObjs.EgressSubmitErrorsNotifications
	readerParams := TrafficEventReaderParams{
		ParentLogger:             logger,
		PodEgressRecords:         podEgressTrafficRecords,
		EgressErrorRecords:       egressErrorRecords,
		PodEgressEvents:          podEgressTrafficEvents,
		EgressErrors:             egressErrors,
		TrafficEventReaderConfig: readerConfig,
	}
	reader, err := NewTrafficEventReader(readerParams)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingTrafficEventReader)
	}
	return &TrafficFactory{
		Logger:               logger,
		cepTrafficObjs:       cepTrafficObjs,
		cepHookers:           xsync.NewIntegerMapOf[int64, *hooker.CiliumCCMHooker](),
		trafficEventHandler:  handler,
		trafficEventReader:   reader,
		TrafficFactoryParams: params,
	}, nil
}

func (f *TrafficFactory) SubscribeToCep(eid int64) error {
	newCepHooker := hooker.NewCiliumCCMHooker(eid)
	cepHooker, _ := f.cepHookers.LoadOrStore(eid, newCepHooker)
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

func (f *TrafficFactory) Close() {
	detachHook := func(eid int64, cepHooker *hooker.CiliumCCMHooker) bool {
		if err := f.detachAllHooks(cepHooker); err != nil {
			f.Error(err)
		}
		return true
	}
	f.cepHookers.Range(detachHook)
	f.cepTrafficObjs.Close()
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
