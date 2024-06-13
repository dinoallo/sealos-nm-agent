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

type HostTrafficEventManagerConfig struct {
	// reader
	TrafficEventReaderConfig
	// handler
	HostTrafficEventHandlerConfig
}

func NewHostTrafficEventManagerConfig() HostTrafficEventManagerConfig {
	return HostTrafficEventManagerConfig{
		TrafficEventReaderConfig:      NewTrafficEventReaderConfig(),
		HostTrafficEventHandlerConfig: NewHostTrafficEventHandlerConfig(),
	}
}

type HostTrafficEventManagerParams struct {
	ParentLogger log.Logger
	Config       HostTrafficEventManagerConfig
	modules.ExportTrafficService
}

type HostTrafficEventManager struct {
	logger                   log.Logger
	trafficObjs              host_trafficObjects
	close                    sync.Once
	deviceHookers            *sync.Map
	trafficEventReaders      map[trafficEventKind]*TrafficEventReader
	hostTrafficEventHandlers map[trafficEventKind]*HostTrafficEventHandler
}

func NewHostTrafficEventManager(params HostTrafficEventManagerParams) (*HostTrafficEventManager, error) {
	logger, err := params.ParentLogger.WithCompName("host_traffic_event_manager")
	if err != nil {
		return nil, errutil.Err(ErrCreatingLogger, err)
	}
	trafficObjs := host_trafficObjects{}
	if err := loadHost_trafficObjects(&trafficObjs, nil); err != nil {
		return nil, errutil.Err(ErrLoadingBPFObjects, err)
	}

	readerParams := TrafficEventReaderParams{
		ParentLogger:             params.ParentLogger,
		TrafficEventReaderConfig: params.Config.TrafficEventReaderConfig,
	}
	handlerParams := HostTrafficEventHandlerParams{
		ParentLogger:                  params.ParentLogger,
		HostTrafficEventHandlerConfig: params.Config.HostTrafficEventHandlerConfig,
		ExportTrafficService:          params.ExportTrafficService,
	}
	trafficEventReaders := make(map[trafficEventKind]*TrafficEventReader)
	hostTrafficEventHandlers := make(map[trafficEventKind]*HostTrafficEventHandler)
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
		handler, err := NewHostTrafficEventHandler(handlerParams)
		if err != nil {
			return err
		}
		hostTrafficEventHandlers[kind] = handler
		return nil
	}
	// ingress
	// IngressEvents := make(chan *perf.Record)
	// if err := setUpReader(trafficObjs.IngressHostTrafficEvents, IngressEvents, Ingress); err != nil {
	// 	return nil, errutil.Err(ErrCreatingEventReader, err)
	// }
	// if err := setUpHandler(IngressEvents, Ingress); err != nil {
	// 	return nil, errutil.Err(ErrCreatingEventHandler, err)
	// }
	// egress
	EgressEvents := make(chan *perf.Record)
	if err := setUpReader(trafficObjs.EgressHostTrafficEvents, EgressEvents, Egress); err != nil {
		return nil, errutil.Err(ErrCreatingEventReader, err)
	}
	if err := setUpHandler(EgressEvents, Egress); err != nil {
		return nil, errutil.Err(ErrCreatingEventHandler, err)
	}

	return &HostTrafficEventManager{
		logger:                   logger,
		trafficObjs:              trafficObjs,
		close:                    sync.Once{},
		deviceHookers:            &sync.Map{},
		trafficEventReaders:      trafficEventReaders,
		hostTrafficEventHandlers: hostTrafficEventHandlers,
	}, nil
}

func (h *HostTrafficEventManager) SubscribeToDevice(iface string) error {
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
	// if err := deviceHooker.AddFilter("sealos_nm_host_traffic_ingress", h.trafficObjs.IngressHostTrafficHook, common.TC_DIR_INGRESS); err != nil {
	// 	return errutil.Err(ErrAddingIngressFilter, err)
	// }
	// h.logger.Infof("add ingress host traffic hook to device %v", iface)
	if err := deviceHooker.AddFilter("sealos_nm_host_traffic_egress", h.trafficObjs.EgressHostTrafficHook, common.TC_DIR_EGRESS); err != nil {
		return errutil.Err(ErrAddingEgressFilter, err)
	}
	h.logger.Infof("add egress host traffic hook to device %v", iface)
	return nil
}

func (h *HostTrafficEventManager) Start(ctx context.Context) error {
	for _, reader := range h.trafficEventReaders {
		reader.Start(ctx)
	}
	for _, handler := range h.hostTrafficEventHandlers {
		handler.Start(ctx)
	}
	return nil
}

func (h *HostTrafficEventManager) Close() {
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
