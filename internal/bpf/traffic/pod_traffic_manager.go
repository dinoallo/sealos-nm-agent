// this is the userspace program
package traffic

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/common"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/hooker"
	errutil "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/errors/util"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

type PodTrafficEventManagerConfig struct {
	// reader
	TrafficEventReaderConfig
	// handler
	PodTrafficEventHandlerConfig
}

func NewPodTrafficEventManagerConfig() PodTrafficEventManagerConfig {
	return PodTrafficEventManagerConfig{
		TrafficEventReaderConfig:     NewTrafficEventReaderConfig(),
		PodTrafficEventHandlerConfig: NewPodTrafficEventHandlerConfig(),
	}
}

type PodTrafficEventManagerParams struct {
	ParentLogger log.Logger
	Config       PodTrafficEventManagerConfig
	modules.ExportTrafficService
}

type PodTrafficEventManager struct {
	logger               log.Logger
	trafficObjs          pod_trafficObjects
	close                sync.Once
	deviceHookers        *sync.Map
	trafficEventReaders  map[trafficEventKind]*TrafficEventReader
	trafficEventHandlers map[trafficEventKind]*PodTrafficEventHandler
}

func NewPodTrafficEventManager(params PodTrafficEventManagerParams) (*PodTrafficEventManager, error) {
	logger, err := params.ParentLogger.WithCompName("pod_traffic_event_manager")
	if err != nil {
		return nil, errutil.Err(ErrCreatingLogger, err)
	}
	trafficObjs := pod_trafficObjects{}
	if err := loadPod_trafficObjects(&trafficObjs, nil); err != nil {
		return nil, errutil.Err(ErrLoadingBPFObjects, err)
	}

	readerParams := TrafficEventReaderParams{
		ParentLogger:             params.ParentLogger,
		TrafficEventReaderConfig: params.Config.TrafficEventReaderConfig,
	}
	handlerParams := PodTrafficEventHandlerParams{
		ParentLogger:                 params.ParentLogger,
		PodTrafficEventHandlerConfig: params.Config.PodTrafficEventHandlerConfig,
		ExportTrafficService:         params.ExportTrafficService,
	}
	trafficEventReaders := make(map[trafficEventKind]*TrafficEventReader)
	trafficEventHandlers := make(map[trafficEventKind]*PodTrafficEventHandler)
	setUpReader := func(perfEvents *ebpf.Map, events chan *perf.Record, kind trafficEventKind) error {
		readerParams.Events = events
		readerParams.PerfEvents = perfEvents
		reader, err := NewTrafficEventReader(readerParams)
		if err != nil {
			return err
		}
		trafficEventReaders[kind] = reader
		return nil
	}
	setUpHandler := func(events chan *perf.Record, kind trafficEventKind) error {
		handlerParams.Events = events
		handler, err := NewPodTrafficEventHandler(handlerParams)
		if err != nil {
			return err
		}
		trafficEventHandlers[kind] = handler
		return nil
	}
	// ingress
	IngressEvents := make(chan *perf.Record)
	if err := setUpReader(trafficObjs.IngressPodTrafficEvents, IngressEvents, Ingress); err != nil {
		return nil, errutil.Err(ErrCreatingEventReader, err)
	}
	if err := setUpHandler(IngressEvents, Ingress); err != nil {
		return nil, errutil.Err(ErrCreatingEventHandler, err)
	}
	// egress
	// EgressEvents := make(chan *perf.Record)
	// if err := setUpReader(trafficObjs.EgressPodTrafficEvents, EgressEvents, Egress); err != nil {
	// 	return nil, errutil.Err(ErrCreatingEventReader, err)
	// }
	// if err := setUpHandler(EgressEvents, Egress); err != nil {
	// 	return nil, errutil.Err(ErrCreatingEventHandler, err)
	// }

	return &PodTrafficEventManager{
		logger:               logger,
		trafficObjs:          trafficObjs,
		close:                sync.Once{},
		deviceHookers:        &sync.Map{},
		trafficEventReaders:  trafficEventReaders,
		trafficEventHandlers: trafficEventHandlers,
	}, nil
}

func (h *PodTrafficEventManager) SubscribeToDevice(iface string) error {
	deviceHooker, err := hooker.NewDeviceHooker(iface, h.logger)
	if err != nil {
		return errutil.Err(ErrCreatingDeviceHooker, err)
	}
	_, loaded := h.deviceHookers.LoadOrStore(iface, deviceHooker)
	if loaded {
		return nil
	}
	if err := deviceHooker.Init(); err != nil {
		return err
	}
	if err := deviceHooker.AddFilter("sealos_nm_pod_traffic_ingress", h.trafficObjs.IngressPodTrafficHook, common.TC_DIR_INGRESS); err != nil {
		return errutil.Err(ErrAddingIngressFilter, err)
	}
	h.logger.Infof("add ingress pod traffic hook to device %v", iface)
	// if err := deviceHooker.AddFilter("sealos_nm_host_traffic_egress", h.trafficObjs.EgressPodTrafficHook, common.TC_DIR_EGRESS); err != nil {
	// 	return errutil.Err(ErrAddingEgressFilter, err)
	// }
	// h.logger.Infof("add egress pod traffic hook to device %v", iface)
	return nil
}

func (h *PodTrafficEventManager) Start(ctx context.Context) error {
	for _, reader := range h.trafficEventReaders {
		reader.Start(ctx)
	}
	for _, handler := range h.trafficEventHandlers {
		handler.Start(ctx)
	}
	return nil
}

func (h *PodTrafficEventManager) Close() {
	h.close.Do(func() {
		closeDeviceHooker := func(key, value any) bool {
			deviceHooker, ok := value.(*hooker.DeviceHooker)
			if !ok {
				// !?
				return true
			}
			err := deviceHooker.Close()
			h.logger.Error(errutil.Err(ErrClosingDeviceHooker, err))
			return true
		}
		h.deviceHookers.Range(closeDeviceHooker)
		h.trafficObjs.Close()
	})
}
