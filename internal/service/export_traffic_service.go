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
	logger          log.Logger
	rawTrafficItems chan *proto.RawTraffic
	conn            *grpc.ClientConn
	ExportTrafficServiceParams
}

func NewExportTrafficService(params ExportTrafficServiceParams) (*ExportTrafficService, error) {
	logger, err := params.ParentLogger.WithCompName("export_traffic_service")
	if err != nil {
		return nil, err
	}
	return &ExportTrafficService{
		logger:                     logger,
		rawTrafficItems:            make(chan *proto.RawTraffic),
		conn:                       nil,
		ExportTrafficServiceParams: params,
	}, nil
}

func (s *ExportTrafficService) Start(ctx context.Context) error {
	wg := errgroup.Group{}
	wg.SetLimit(s.MaxWorkerCount)
	conn, err := grpc.Dial(s.TrafficExporterAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithKeepaliveParams(
		keepalive.ClientParameters{
			Time:    10 * time.Second,
			Timeout: 5 * time.Second,
		},
	))
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
				wg.Go(func() error {
					s.sendRawTrafficItem(ctx)
					return nil
				})
			}
		}
	}()
	return nil
}

func (s *ExportTrafficService) sendRawTrafficItem(ctx context.Context) {
	client := proto.NewTrafficExportServiceClient(s.conn)
	stream, err := client.ExportTraffic(ctx)
	if err != nil {
		s.logger.Errorf("failed to open a stream to send a raw traffic item: %v", err)
		return
	}
	for {
		select {
		case item := <-s.rawTrafficItems:
			err := stream.Send(item)
			if err != nil {
				s.logger.Errorf("failed to send a raw traffic item: %v", err)
				continue
			}
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				s.logger.Errorf("failed to close the stream: %v", err)
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

func (s *ExportTrafficService) SubmitRawTrafficEvent(ctx context.Context, e structs.RawTrafficEvent) error {
	item := convert(e)
	select {
	case s.rawTrafficItems <- item:
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
