package traffic

import (
	"context"
	"errors"
	"time"

	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"golang.org/x/sync/errgroup"
)

const (
	defaultSendTimeout = time.Second * 1
)

type TrafficEventReaderConfig struct {
	MaxWorker           int
	PerfEventBufferSize int
}

type TrafficEventReaderParams struct {
	ParentLogger        log.Logger
	PodEgressPerfEvents *ebpf.Map
	PodEgressEvents     chan *perf.Record
	TrafficEventReaderConfig
}

type TrafficEventReader struct {
	log.Logger
	podEgressPerfEventReader *perf.Reader //TODO: implement ringbuf reader
	TrafficEventReaderParams
}

func NewTrafficEventReader(params TrafficEventReaderParams) (*TrafficEventReader, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_reader")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	podEgressPerfEventReader, err := perf.NewReader(params.PodEgressPerfEvents, params.PerfEventBufferSize)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingPodEgressPerfEventReader)
	}
	return &TrafficEventReader{
		Logger:                   logger,
		podEgressPerfEventReader: podEgressPerfEventReader,
		TrafficEventReaderParams: params,
	}, nil
}

func (r *TrafficEventReader) Start(ctx context.Context) {
	doReading(ctx, r.MaxWorker, r.readPodEgress, r.Logger)
}

func (r *TrafficEventReader) readPodEgress(ctx context.Context) error {
	record, err := r.podEgressPerfEventReader.Read()
	if errors.Is(err, perf.ErrClosed) {
		r.Infof("the reader is closed for pod egress perf events")
		return nil
	} else if err != nil {
		return errors.Join(err, modules.ErrReadingFromPerfEventReader)
	}
	//TODO: keep track of this
	if record.LostSamples != 0 {
		r.Infof("the perf event buffer for pod egress is full, so %v samples were dropped", record.LostSamples)
		return nil
	}
	sendCtx, cancel := context.WithTimeout(ctx, defaultSendTimeout)
	defer cancel()
	select {
	case <-sendCtx.Done():
		return nil
	case r.PodEgressEvents <- &record:
		return nil
	}
}

func doReading(ctx context.Context, workerCount int, readFunc func(context.Context) error, logger log.Logger) {
	wg := errgroup.Group{}
	wg.SetLimit(workerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					if err := readFunc(ctx); err != nil {
						logger.Error("failed to read: %v", err)
						return err
					}
					return nil
				})
			}
		}
	}()
}
