package traffic

import (
	"context"
	"errors"
	"os"
	"time"

	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"

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
	ParentLogger             log.Logger
	TrafficObjs              *trafficObjects
	EgressPodTrafficRecords  chan *ringbuf.Record
	EgressHostTrafficRecords chan *ringbuf.Record
	EgressPodNotiRecords     chan *ringbuf.Record
	EgressHostNotiRecords    chan *ringbuf.Record
	TrafficEventReaderConfig
}

type TrafficEventReader struct {
	log.Logger
	egressPodTrafficReader  *ringbuf.Reader
	egressHostTrafficReader *ringbuf.Reader
	egressPodNotiReader     *ringbuf.Reader
	egressHostNotiReader    *ringbuf.Reader
	TrafficEventReaderParams
}

func NewTrafficEventReader(params TrafficEventReaderParams) (*TrafficEventReader, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_event_reader")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	egressPodTrafficReader, err := ringbuf.NewReader(params.TrafficObjs.FromContainerTrafficEvents)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingEgressPodTrafficReader)
	}
	egressHostTrafficReader, err := ringbuf.NewReader(params.TrafficObjs.ToNetdevTrafficEvents)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingEgressHostTrafficReader)
	}
	egressPodNotiReader, err := ringbuf.NewReader(params.TrafficObjs.FromContainerTrafficNotis)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingEgressPodNotiReader)
	}
	egressHostNotiReader, err := ringbuf.NewReader(params.TrafficObjs.ToNetdevTrafficNotis)
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingEgressHostNotiReader)
	}
	return &TrafficEventReader{
		Logger:                   logger,
		egressPodTrafficReader:   egressPodTrafficReader,
		egressHostTrafficReader:  egressHostTrafficReader,
		egressPodNotiReader:      egressPodNotiReader,
		egressHostNotiReader:     egressHostNotiReader,
		TrafficEventReaderParams: params,
	}, nil
}

func (r *TrafficEventReader) Start(ctx context.Context) {
	r.startReading(ctx, "pod_egress_reader", "pod_egress_chan", r.egressPodTrafficReader, r.EgressPodTrafficRecords)
	r.startReading(ctx, "pod_noti_reader", "pod_noti_chan", r.egressPodNotiReader, r.EgressPodNotiRecords)
	r.startReading(ctx, "host_egress_reader", "host_egress_chan", r.egressHostTrafficReader, r.EgressHostTrafficRecords)
	r.startReading(ctx, "host_noti_reader", "host_noti_chan", r.egressHostNotiReader, r.EgressHostNotiRecords)
}

func (r *TrafficEventReader) startReading(ctx context.Context, readerName, recordChanName string, reader *ringbuf.Reader, recordChan chan *ringbuf.Record) {
	go func() {
		wg := errgroup.Group{}
		wg.SetLimit(r.MaxWorker)
		for {
			select {
			case <-ctx.Done():
				reader.Close()
				return
			default:
				wg.Go(func() error {
					if err := r.read(ctx, readerName, recordChanName, reader, recordChan); err != nil {
						r.Error("failed to read error: %v", err)
						return err
					}
					return nil
				})
			}
		}
	}()
}

func (r *TrafficEventReader) read(ctx context.Context, readerName, recordChanName string, reader *ringbuf.Reader, recordChan chan *ringbuf.Record) error {
	reader.SetDeadline(time.Now().Add(r.ReadingTimeout))
	record, err := reader.Read()
	if errors.Is(err, ringbuf.ErrClosed) {
		r.Infof("reader %v has been closed", readerName)
		return nil
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil
	} else if err != nil {
		return errors.Join(err, modules.ErrReadingFromRingBuf)
	}
	sendCtx, cancel := context.WithTimeout(ctx, defaultSendTimeout)
	defer cancel()
	select {
	case <-sendCtx.Done():
		r.Infof("timeout sending this record to record chan %v. drop this record", recordChanName)
		return nil
	case recordChan <- &record:
		return nil
	}
}
