package traffic

import (
	"context"
	"errors"
	"os"
	"time"

	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"golang.org/x/sync/errgroup"
)

const (
	defaultSendTimeout = time.Second * 1
)

type TrafficEventReaderConfig struct {
	MaxWorker      int
	ReadingTimeout time.Duration
}

type TrafficEventReaderParams struct {
	ParentLogger       log.Logger
	PodEgressEvents    *ebpf.Map
	EgressErrors       *ebpf.Map
	PodEgressRecords   chan *ringbuf.Record
	EgressErrorRecords chan *ringbuf.Record
	TrafficEventReaderConfig
}

type TrafficEventReader struct {
	log.Logger
	podEgressEventReader *ringbuf.Reader
	egressErrorsReader   *ringbuf.Reader
	TrafficEventReaderParams
}

func NewTrafficEventReader(params TrafficEventReaderParams) (*TrafficEventReader, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_reader")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	podEgressEventReader, err := ringbuf.NewReader(params.PodEgressEvents)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingPodEgressEventRingBufReader)
	}
	egressErrorsReader, err := ringbuf.NewReader(params.EgressErrors)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingEgressErrorEventRingBufReader)
	}
	return &TrafficEventReader{
		Logger:                   logger,
		podEgressEventReader:     podEgressEventReader,
		egressErrorsReader:       egressErrorsReader,
		TrafficEventReaderParams: params,
	}, nil
}

func (r *TrafficEventReader) Start(ctx context.Context) {
	wg := errgroup.Group{}
	wg.SetLimit(r.MaxWorker)
	go func() {
		for {
			select {
			case <-ctx.Done():
				r.podEgressEventReader.Close()
				return
			default:
				wg.Go(func() error {
					if err := r.readPodEgress(ctx); err != nil {
						r.Error("failed to read: %v", err)
						return err
					}
					return nil
				})
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				r.egressErrorsReader.Close()
				return
			default:
				if err := r.readEgressErrors(ctx); err != nil {
					r.Error("failed to read error: %v", err)
				}
			}
		}
	}()
}

func (r *TrafficEventReader) readPodEgress(ctx context.Context) error {
	r.podEgressEventReader.SetDeadline(time.Now().Add(r.ReadingTimeout))
	record, err := r.podEgressEventReader.Read()
	if errors.Is(err, ringbuf.ErrClosed) {
		r.Infof("the reader is closed for pod egress events")
		return nil
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		r.Errorf("timeout getting a pod egress record")
		return nil
	} else if err != nil {
		return errors.Join(err, modules.ErrReadingFromEventRingBufReader)
	}
	sendCtx, cancel := context.WithTimeout(ctx, defaultSendTimeout)
	defer cancel()
	select {
	case <-sendCtx.Done():
		r.Infof("timeout sending this pod egress record to the handler. drop this record")
		return nil
	case r.PodEgressRecords <- &record:
		return nil
	}
}

func (r *TrafficEventReader) readEgressErrors(ctx context.Context) error {
	r.egressErrorsReader.SetDeadline(time.Now().Add(r.ReadingTimeout))
	record, err := r.egressErrorsReader.Read()
	if errors.Is(err, ringbuf.ErrClosed) {
		r.Infof("the reader is closed for egress error eventts")
		return nil
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil
	} else if err != nil {
		return errors.Join(err, modules.ErrReadingFromErrorRingBufReader)
	}
	sendCtx, cancel := context.WithTimeout(ctx, defaultSendTimeout)
	defer cancel()
	select {
	case <-sendCtx.Done():
		r.Infof("timeout sending this error record to the handler. drop this record")
		return nil
	case r.EgressErrorRecords <- &record:
		return nil
	}
}
