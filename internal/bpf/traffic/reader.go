package traffic

import (
	"context"
	"errors"

	"time"

	"github.com/dinoallo/sealos-networkmanager-library/pkg/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sync/errgroup"
)

type TrafficEventReaderConfig struct {
	WorkerCount         int
	PerfEventBufferSize int
}

func NewTrafficEventReaderConfig() TrafficEventReaderConfig {
	return TrafficEventReaderConfig{
		WorkerCount:         1,
		PerfEventBufferSize: (32 << 10), // 32KB
	}
}

type TrafficEventReaderParams struct {
	ParentLogger log.Logger
	PerfEvents   *ebpf.Map
	Events       chan *perf.Record
	TrafficEventReaderConfig
}

type TrafficEventReader struct {
	logger          log.Logger
	perfEventReader *perf.Reader //TODO: implement ringbuf reader
	TrafficEventReaderParams
}

func NewTrafficEventReader(params TrafficEventReaderParams) (*TrafficEventReader, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_reader")
	if err != nil {
		return nil, err
	}
	perfEventReader, err := perf.NewReader(params.PerfEvents, params.PerfEventBufferSize)
	if err != nil {
		return nil, err
	}
	return &TrafficEventReader{
		logger:                   logger,
		perfEventReader:          perfEventReader,
		TrafficEventReaderParams: params,
	}, nil
}

func (r *TrafficEventReader) Start(ctx context.Context) error {
	wg := errgroup.Group{}
	wg.SetLimit(r.WorkerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					_ctx, cancel := context.WithTimeout(ctx, time.Second*1) //TODO: make this configurable
					defer cancel()
					return r.read(_ctx)
				})
			}
		}
	}()
	return nil
}

func (r *TrafficEventReader) read(ctx context.Context) error {
	record, err := r.perfEventReader.Read()
	if errors.Is(err, perf.ErrClosed) {
		r.logger.Info("the perf event channel is closed")
		return nil
	} else if err != nil {
		return err
	}
	//TODO: keep track of this
	if record.LostSamples != 0 {
		r.logger.Infof("the perf event ring buffer is full, so %d samples were dropped", record.LostSamples)
	}
	select {
	case <-ctx.Done():
		return nil
	case r.Events <- &record:
		return nil
	}
}
