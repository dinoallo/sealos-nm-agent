package traffic

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
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
	trafficEventReader  *TrafficEventReader
	trafficEventHandler *TrafficEventHandler
	hostNetnsAlias      string
	TrafficFactoryParams
}

func NewTrafficFactory(params TrafficFactoryParams) (*TrafficFactory, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_factory")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	trafficObjs := trafficObjects{}
	if err := loadTrafficObjects(&trafficObjs, nil); err != nil {
		return nil, errors.Join(err, modules.ErrLoadingTrafficObjs)
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
	hostNetnsAlias := generateRandomHashForHostNet()
	return &TrafficFactory{
		Logger:               logger,
		trafficObjs:          trafficObjs,
		hostNetnsAlias:       hostNetnsAlias,
		trafficEventHandler:  handler,
		trafficEventReader:   reader,
		TrafficFactoryParams: params,
	}, nil
}

func (f *TrafficFactory) Start(ctx context.Context) error {
	f.trafficEventReader.Start(ctx)
	f.trafficEventHandler.Start(ctx)
	return nil
}

func (f *TrafficFactory) GetEgressFilterFDForHostDev() int {
	return f.trafficObjs.SealosToNetdev.FD()
}

func (f *TrafficFactory) GetEgressFilterFDForPodDev() int {
	return f.trafficObjs.SealosFromContainer.FD()
}

func (f *TrafficFactory) Close() {
	f.trafficObjs.Close()
}

func getPodIfaceHash(ifaceName string) string {
	//TODO: imple me
	return ifaceName
}

func getNetnsHash(netnsName string) string {
	return netnsName
}

func generateRandomHashForHostNet() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b) + time.Now().Format("20060102150405")
}
