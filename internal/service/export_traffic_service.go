package service

import (
	"context"
	"io"
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
					s.assignRawPodTrafficItems(ctx)
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
					s.assignRawHostTrafficItems(ctx)
					return nil
				})
			}
		}
	}()
	return nil
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

func (s *ExportTrafficService) assignRawPodTrafficItems(ctx context.Context) {
	recvCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	var items []*proto.RawTraffic
	var itemCount int = 0
collecting_loop:
	for {
		select {
		case item := <-s.rawPodTrafficItems:
			items = append(items, item)
			itemCount++
			if itemCount == 100 {
				//TODO: make this configurable
				break collecting_loop
			}
		case <-recvCtx.Done():
			//s.logger.Debugf("no more traffic items ready to be sent. prepare to send what we already have")
			break collecting_loop
		case <-ctx.Done():
			s.logger.Infof("assigning cancelled since the context is cancelled")
			return
		}
	}
	if len(items) <= 0 {
		return
	}
	//	s.logger.Debugf("try to send %v traffic items", len(items))
	if err := s.sendRawPodTrafficItem(items); err != nil {
		s.logger.Errorf("failed to send some traffic items: %v", err)
		return
	}
	//	s.logger.Debugf("%v traffic items successfully sent", len(items))
	return
}

func (s *ExportTrafficService) sendRawPodTrafficItem(items []*proto.RawTraffic) error {
	client := proto.NewTrafficExportServiceClient(s.conn)
	stream, err := client.ExportPodTraffic(context.TODO())
	if err != nil {
		s.logger.Errorf("failed to open a stream to send a raw traffic item: %v", err)
		return err
	}
	for _, item := range items {
		err := stream.Send(item)
		if err == io.EOF {
			s.logger.Infof("EOF returned while sending. abort the remaining items")
			break
		} else if err != nil {
			s.logger.Errorf("failed to sent raw traffic item %+v: %v", item, err)
			continue
		}
	}
	_, err = stream.CloseAndRecv()
	if err != nil {
		return err
	}
	return nil
}

func (s *ExportTrafficService) assignRawHostTrafficItems(ctx context.Context) {
	recvCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	var items []*proto.RawTraffic
	var itemCount int = 0
collecting_loop:
	for {
		select {
		case item := <-s.rawHostTrafficItems:
			items = append(items, item)
			itemCount++
			if itemCount == 100 {
				//TODO: make this configurable
				break collecting_loop
			}
		case <-recvCtx.Done():
			// s.logger.Debugf("no more traffic items ready to be sent. prepare to send what we already have")
			break collecting_loop
		case <-ctx.Done():
			s.logger.Infof("assigning cancelled since the context is cancelled")
			return
		}
	}
	if len(items) <= 0 {
		return
	}
	// s.logger.Debugf("try to send %v traffic items", len(items))
	if err := s.sendRawHostTrafficItem(items); err != nil {
		s.logger.Errorf("failed to send some traffic items: %v", err)
		return
	}
	// s.logger.Debugf("%v traffic items successfully sent", len(items))
	return
}

func (s *ExportTrafficService) sendRawHostTrafficItem(items []*proto.RawTraffic) error {
	client := proto.NewTrafficExportServiceClient(s.conn)
	stream, err := client.ExportHostTraffic(context.TODO())
	if err != nil {
		s.logger.Errorf("failed to open a stream to send a raw traffic item: %v", err)
		return err
	}
	for _, item := range items {
		err := stream.Send(item)
		if err == io.EOF {
			// s.logger.Infof("EOF returned while sending. abort the remaining items")
			break
		} else if err != nil {
			s.logger.Errorf("failed to sent raw traffic item %+v: %v", item, err)
			continue
		}
	}
	_, err = stream.CloseAndRecv()
	if err != nil {
		return err
	}
	return nil
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
