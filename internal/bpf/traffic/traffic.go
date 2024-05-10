// this is the userspace program
package traffic

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/bpf/common"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/bpf/hooker"
	errutil "github.com/dinoallo/sealos-networkmanager-library/pkg/errors/util"
	"github.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

type trafficEventKind uint32

const (
	Ingress trafficEventKind = iota
	Egress
)

type TrafficEventManagerConfig struct {
	// reader
	TrafficEventReaderConfig
	// handler
	TrafficEventHandlerConfig
}

func NewTrafficEventManagerConfig() TrafficEventManagerConfig {
	return TrafficEventManagerConfig{
		TrafficEventReaderConfig:  NewTrafficEventReaderConfig(),
		TrafficEventHandlerConfig: NewTrafficEventHandlerConfig(),
	}
}

type TrafficEventManagerParams struct {
	ParentLogger log.Logger
	Config       TrafficEventManagerConfig
	modules.RawTrafficStore
}

type TrafficEventManager struct {
	logger               log.Logger
	trafficObjs          trafficObjects
	close                sync.Once
	deviceHookers        *sync.Map
	trafficEventReaders  map[trafficEventKind]*TrafficEventReader
	trafficEventHandlers map[trafficEventKind]*TrafficEventHandler
}

func NewTrafficEventManager(params TrafficEventManagerParams) (*TrafficEventManager, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_manager")
	if err != nil {
		return nil, errutil.Err(ErrCreatingLogger, err)
	}
	trafficObjs := trafficObjects{}
	if err := loadTrafficObjects(&trafficObjs, nil); err != nil {
		return nil, errutil.Err(ErrLoadingBPFObjects, err)
	}

	readerParams := TrafficEventReaderParams{
		ParentLogger:             params.ParentLogger,
		TrafficEventReaderConfig: params.Config.TrafficEventReaderConfig,
	}
	handlerParams := TrafficEventHandlerParams{
		ParentLogger:              params.ParentLogger,
		TrafficEventHandlerConfig: params.Config.TrafficEventHandlerConfig,
		RawTrafficStore:           params.RawTrafficStore,
	}
	trafficEventReaders := make(map[trafficEventKind]*TrafficEventReader)
	trafficEventHandlers := make(map[trafficEventKind]*TrafficEventHandler)
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
		handler, err := NewTrafficEventHandler(handlerParams)
		if err != nil {
			return err
		}
		trafficEventHandlers[kind] = handler
		return nil
	}
	// egress
	EgressEvents := make(chan *perf.Record)
	if err := setUpReader(trafficObjs.EgressTrafficEvents, EgressEvents, Egress); err != nil {
		return nil, errutil.Err(ErrCreatingEventReader, err)
	}
	if err := setUpHandler(EgressEvents, Egress); err != nil {
		return nil, errutil.Err(ErrCreatingEventHandler, err)
	}

	return &TrafficEventManager{
		logger:               logger,
		trafficObjs:          trafficObjs,
		close:                sync.Once{},
		deviceHookers:        &sync.Map{},
		trafficEventReaders:  trafficEventReaders,
		trafficEventHandlers: trafficEventHandlers,
	}, nil
}

func (h *TrafficEventManager) SubscribeToDevice(iface string) error {
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
	//TODO: set up ingress hook
	if err := deviceHooker.AddFilter("sealos_nm_traffic_egress", h.trafficObjs.EgressTrafficHook, common.TC_DIR_EGRESS); err != nil {
		return errutil.Err(ErrAddingEgressFilter, err)
	}
	return nil
}

func (h *TrafficEventManager) Start(ctx context.Context) error {
	for _, reader := range h.trafficEventReaders {
		reader.Start(ctx)
	}
	for _, handler := range h.trafficEventHandlers {
		handler.Start(ctx)
	}
	return nil
}

func (h *TrafficEventManager) Close() {
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
