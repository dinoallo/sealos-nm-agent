package service

import (
	"context"
	"net"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/bytecount"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store/cilium_endpoint"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto/agent"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

const (
	DEFAULT_TRAFFIC_SERVICE_ADDRESS = "0.0.0.0:5005"
)

type TrafficServiceParam struct {
	ParentLogger *zap.SugaredLogger
	BF           *bytecount.BytecountFactoryInterface
	CES          *cilium_endpoint.CiliumEndpointStoreInterface
}

type TrafficService struct {
	counterpb.UnimplementedCountingServiceServer
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
	counterpb.RegisterCountingServiceServer(s.svcRegistrar, s)
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
	lis, err := net.Listen("tcp", DEFAULT_TRAFFIC_SERVICE_ADDRESS)
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

func (s *TrafficService) CreateCounter(ctx context.Context, in *counterpb.CreateCounterRequest) (*counterpb.Empty, error) {
	if in == nil {
		return new(counterpb.Empty), util.ErrRequestNotPassed
	}
	bf := s.param.BF
	if bf == nil {
		return new(counterpb.Empty), util.ErrFactoryNotInited
	}
	cepStore := s.param.CES
	if cepStore == nil {
		return new(counterpb.Empty), util.ErrStoreNotInited
	}
	counter := in.GetCounter()
	eid := counter.GetEndpointId()
	_dir := counter.GetDirection()
	cleanUp := in.GetCleanUp()

	var dir consts.TrafficDirection
	switch _dir {
	case counterpb.Direction_V4Ingress:
		dir = consts.TRAFFIC_DIR_V4_INGRESS
	case counterpb.Direction_V4Egress:
		dir = consts.TRAFFIC_DIR_V4_EGRESS
	default:
		return new(counterpb.Empty), util.ErrUnknownDirection
	}
	if exists, err := cepStore.FindCEP(ctx, eid); err != nil {
		return nil, err
	} else if exists && !cleanUp {
		// if the counter is already created, avoid creating the counter again
		return new(counterpb.Empty), nil
	} else {
		if err := bf.CreateCounter(ctx, eid, dir); err != nil {
			return new(counterpb.Empty), err
		}
		return new(counterpb.Empty), cepStore.Create(ctx, eid)
	}
}

// the following apis have been deprecated
func (s *TrafficService) Subscribe(ctx context.Context, in *counterpb.SubscribeRequest) (*counterpb.Empty, error) {
	return new(counterpb.Empty), nil
}

func (s *TrafficService) Unsubscribe(ctx context.Context, in *counterpb.UnsubscribeRequest) (*counterpb.Empty, error) {
	return new(counterpb.Empty), nil
}

func (s *TrafficService) DumpTraffic(ctx context.Context, in *counterpb.DumpTrafficRequest) (*counterpb.DumpTrafficResponse, error) {
	return nil, nil
}
