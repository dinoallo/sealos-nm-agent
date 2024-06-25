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
	ParentLogger         log.Logger
	HostEgressPerfEvents *ebpf.Map
	PodIngressPerfEvents *ebpf.Map
	HostEgressEvents     chan *perf.Record
	PodIngressEvents     chan *perf.Record
	TrafficEventReaderConfig
}

type TrafficEventReader struct {
	log.Logger
	hostEgressPerfEventReader *perf.Reader
	podIngressPerfEventReader *perf.Reader //TODO: implement ringbuf reader
	TrafficEventReaderParams
}

func NewTrafficEventReader(params TrafficEventReaderParams) (*TrafficEventReader, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_reader")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	hostEgressPerfEventReader, err := perf.NewReader(params.HostEgressPerfEvents, params.PerfEventBufferSize)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingHostEgressPerfEventReader)
	}
	podIngressPerfEventReader, err := perf.NewReader(params.PodIngressPerfEvents, params.PerfEventBufferSize)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingPodIngressPerfEventReader)
	}
	return &TrafficEventReader{
		Logger:                    logger,
		hostEgressPerfEventReader: hostEgressPerfEventReader,
		podIngressPerfEventReader: podIngressPerfEventReader,
		TrafficEventReaderParams:  params,
	}, nil
}

func (r *TrafficEventReader) Start(ctx context.Context) {
	doReading(ctx, r.MaxWorker, r.readHostEgress, r.Logger)
	doReading(ctx, r.MaxWorker, r.readPodIngress, r.Logger)
}

func (r *TrafficEventReader) readHostEgress(ctx context.Context) error {
	record, err := r.hostEgressPerfEventReader.Read()
	if errors.Is(err, perf.ErrClosed) {
		r.Infof("the reader is closed for host egress perf events")
		return nil
	} else if err != nil {
		return errors.Join(err, modules.ErrReadingFromPerfEventReader)
	}
	//TODO: keep track of this
	if record.LostSamples != 0 {
		r.Infof("the perf event buffer for host egress is full, so %v samples were dropped", record.LostSamples)
		return nil
	}
	sendCtx, cancel := context.WithTimeout(ctx, defaultSendTimeout)
	defer cancel()
	select {
	case <-sendCtx.Done():
		return nil
	case r.HostEgressEvents <- &record:
		return nil
	}
}

func (r *TrafficEventReader) readPodIngress(ctx context.Context) error {
	record, err := r.podIngressPerfEventReader.Read()
	if errors.Is(err, perf.ErrClosed) {
		r.Infof("the reader is closed for pod ingress perf events")
		return nil
	} else if err != nil {
		return errors.Join(err, modules.ErrReadingFromPerfEventReader)
	}
	//TODO: keep track of this
	if record.LostSamples != 0 {
		r.Infof("the perf event buffer for pod ingress is full, so %v samples were dropped", record.LostSamples)
		return nil
	}
	sendCtx, cancel := context.WithTimeout(ctx, defaultSendTimeout)
	defer cancel()
	select {
	case <-sendCtx.Done():
		return nil
	case r.PodIngressEvents <- &record:
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
