package service

import (
	"context"
	"fmt"
	"net"
	"time"

	counterpb "github.com/dinoallo/sealos-networkmanager-agent/api/proto/agent"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/bytecount"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/cilium_endpoint"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

type TrafficServiceParam struct {
	ParentLogger *zap.SugaredLogger
	BF           *bytecount.BytecountFactoryInterface
	CES          *cilium_endpoint.CiliumEndpointStoreInterface
}

type TrafficService struct {
	counterpb.UnimplementedTrafficServiceServer
	name         string
	logger       *zap.SugaredLogger
	param        TrafficServiceParam
	cfg          conf.TrafficServiceConfig
	svcRegistrar *grpc.Server
}

func NewTrafficService(param TrafficServiceParam, cfg conf.TrafficServiceConfig) (*TrafficService, error) {
	svcRegistrar := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: time.Duration(cfg.MaxConnectionIdle) * time.Second}))
	name := "traffic_service"
	return &TrafficService{
		name:         name,
		logger:       param.ParentLogger.With("component", name),
		param:        param,
		cfg:          cfg,
		svcRegistrar: svcRegistrar,
	}, nil
}

func (s *TrafficService) Launch(ctx context.Context, mainEg *errgroup.Group) error {
	if s.svcRegistrar == nil {
		return util.ErrServiceRegistrarNotInited
	}
	counterpb.RegisterTrafficServiceServer(s.svcRegistrar, s)
	reflection.Register(s.svcRegistrar)
	mainEg.Go(func() error {
		return s.serve(ctx)
	})
	return nil
}

func (s *TrafficService) Stop(ctx context.Context) error {
	if s.svcRegistrar == nil {
		return nil
	}
	s.svcRegistrar.GracefulStop()
	return nil
}

func (s *TrafficService) GetName() string {
	return s.name
}

func (s *TrafficService) serve(ctx context.Context) error {
	svcRegistrar := s.svcRegistrar
	if svcRegistrar == nil {
		return util.ErrServiceRegistrarNotInited
	}
	logger := s.logger
	if logger == nil {
		return util.ErrLoggerNotInited
	}
	addr := fmt.Sprintf("0.0.0.0:%v", s.cfg.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	serveEg := errgroup.Group{}
	serveEg.SetLimit(1)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			serveEg.Go(func() error {
				if err := svcRegistrar.Serve(lis); err != nil {
					logger.Errorf("failed to serve: %v", err)
				}
				return nil
			})
		}
	}
}

func (s *TrafficService) CreateTrafficCounter(ctx context.Context, in *counterpb.CreateTrafficCounterRequest) (*counterpb.CreateTrafficCounterResponse, error) {
	if in == nil {
		return getResp(counterpb.Code_INVALID_ARGUMENT, "CreateTrafficCounterRequest is not passed"), util.ErrRequestNotPassed
	}
	bf := s.param.BF
	cepStore := s.param.CES
	counter := in.GetCounter()
	eid := counter.GetEndpointId()
	_dir := counter.GetDirection()

	var dir consts.TrafficDirection
	switch _dir {
	case counterpb.Direction_V4Ingress:
		dir = consts.TRAFFIC_DIR_V4_INGRESS
	case counterpb.Direction_V4Egress:
		dir = consts.TRAFFIC_DIR_V4_EGRESS
	default:
		return getResp(counterpb.Code_UNIMPLEMENTED, "the direction is not currently implemented"), util.ErrUnknownDirection
	}
	if err := bf.CreateCounter(ctx, eid, dir); err != nil {
		switch err {
		case util.ErrBPFCustomCallMapNotExist:
			return getResp(counterpb.Code_NOT_FOUND, err.Error()), err
		case util.ErrBPFMapNotLoaded:
			return getResp(counterpb.Code_INTERNAL, err.Error()), err
		case util.ErrBPFMapNotUpdated:
			return getResp(counterpb.Code_INTERNAL, err.Error()), err
		}
	}
	if err := cepStore.Create(ctx, eid); err != nil {
		return getResp(counterpb.Code_INTERNAL, err.Error()), err
	}
	return getResp(counterpb.Code_OK, "counter created"), nil
}
