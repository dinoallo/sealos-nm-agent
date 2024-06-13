package service

import (
	"context"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/api/proto"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var (
	kacp = keepalive.ClientParameters{
		Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
		Timeout:             time.Second,      // wait 1 second for ping ack before considering the connection dead
		PermitWithoutStream: true,             // send pings even without active streams
	}
	insecureCreds = insecure.NewCredentials()
)

type ExportTrafficServiceConfig struct {
	MaxWorkerCount      int
	TrafficExporterAddr string
}

func NewExportTrafficServiceConfig() ExportTrafficServiceConfig {
	return ExportTrafficServiceConfig{
		MaxWorkerCount:      5,
		TrafficExporterAddr: "localhost:50050",
	}
}

type ExportTrafficServiceParams struct {
	ParentLogger log.Logger
	ExportTrafficServiceConfig
}

type ExportTrafficService struct {
	logger              log.Logger
	rawHostTrafficItems chan *proto.RawTraffic
	rawPodTrafficItems  chan *proto.RawTraffic
	conn                *grpc.ClientConn
	ExportTrafficServiceParams
}

func NewExportTrafficService(params ExportTrafficServiceParams) (*ExportTrafficService, error) {
	logger, err := params.ParentLogger.WithCompName("export_traffic_service")
	if err != nil {
		return nil, err
	}
	return &ExportTrafficService{
		logger:                     logger,
		rawHostTrafficItems:        make(chan *proto.RawTraffic),
		rawPodTrafficItems:         make(chan *proto.RawTraffic),
		conn:                       nil,
		ExportTrafficServiceParams: params,
	}, nil
}

func (s *ExportTrafficService) Start(ctx context.Context) error {
	pWg := errgroup.Group{}
	pWg.SetLimit(s.MaxWorkerCount)
	hWg := errgroup.Group{}
	hWg.SetLimit(s.MaxWorkerCount)
	conn, err := grpc.NewClient(s.TrafficExporterAddr, grpc.WithTransportCredentials(insecureCreds), grpc.WithKeepaliveParams(kacp))
	if err != nil {
		return err
	}
	s.conn = conn
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				pWg.Go(func() error {
					s.sendRawPodTrafficItem(ctx)
					return nil
				})
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				hWg.Go(func() error {
					s.sendRawHostTrafficItem(ctx)
					return nil
				})
			}
		}
	}()
	return nil
}

func (s *ExportTrafficService) sendRawPodTrafficItem(ctx context.Context) {
	client := proto.NewTrafficExportServiceClient(s.conn)
	stream, err := client.ExportPodTraffic(ctx)
	if err != nil {
		s.logger.Errorf("failed to open a stream to send a raw traffic item: %v", err)
		return
	}
	for {
		select {
		case item := <-s.rawPodTrafficItems:
			err := stream.Send(item)
			if err != nil {
				s.logger.Errorf("failed to send a raw traffic item: %v", err)
				return
			}
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				s.logger.Errorf("failed to close the stream: %v", err)
				return
			}
			return
		}
	}
}

func (s *ExportTrafficService) sendRawHostTrafficItem(ctx context.Context) {
	client := proto.NewTrafficExportServiceClient(s.conn)
	stream, err := client.ExportHostTraffic(ctx)
	if err != nil {
		s.logger.Errorf("failed to open a stream to send a raw traffic item: %v", err)
		return
	}
	for {
		select {
		case item := <-s.rawHostTrafficItems:
			err := stream.Send(item)
			if err != nil {
				s.logger.Errorf("failed to send a raw traffic item: %v", err)
				return
			}
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				s.logger.Errorf("failed to close the stream: %v", err)
				return
			}
			return
		}
	}
}

func convert(e structs.RawTrafficEvent) *proto.RawTraffic {
	return &proto.RawTraffic{
		Meta: &proto.RawTrafficMetaData{
			SrcIp:    e.RawTrafficEventMeta.SrcIP,
			DstIp:    e.RawTrafficEventMeta.DstIP,
			SrcPort:  e.RawTrafficEventMeta.SrcPort,
			DstPort:  e.RawTrafficEventMeta.DstPort,
			Protocol: e.RawTrafficEventMeta.Protocol,
			Family:   e.RawTrafficEventMeta.Family,
		},
		Metric: &proto.RawTrafficMetric{
			DataBytes: e.DataBytes,
		},
	}
}

func (s *ExportTrafficService) SubmitRawPodTrafficEvent(ctx context.Context, e structs.RawTrafficEvent) error {
	item := convert(e)
	select {
	case s.rawPodTrafficItems <- item:
	case <-ctx.Done():
		return modules.ErrTimeoutSubmittingRTE
	}
	return nil
}

func (s *ExportTrafficService) SubmitRawHostTrafficEvent(ctx context.Context, e structs.RawTrafficEvent) error {
	item := convert(e)
	select {
	case s.rawHostTrafficItems <- item:
	case <-ctx.Done():
		return modules.ErrTimeoutSubmittingRTE
	}
	return nil
}

func (s *ExportTrafficService) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}
