package service

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/bpf/bytecount"
	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto/agent"
	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

const (
	DEFAULT_TRAFFIC_SERVICE_ADDRESS = "0.0.0.0:50051"
)

type TrafficService struct {
	counterpb.UnimplementedCountingServiceServer
	name                string
	logger              *zap.SugaredLogger
	bytecountFactory    *bytecount.Factory
	ciliumEndpointStore *store.CiliumEndpointStore
	svcRegistrar        *grpc.Server
}

func NewTrafficService(baseLogger *zap.SugaredLogger, bf *bytecount.Factory, cepStore *store.CiliumEndpointStore) (*TrafficService, error) {
	if baseLogger == nil || bf == nil {
		return nil, fmt.Errorf("both the base logger and the factory shouldn't be nil")
	}
	svcRegistrar := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    15 * time.Second,
			Timeout: 5 * time.Second,
		}))
	name := "traffic_service"
	return &TrafficService{
		name:                name,
		logger:              baseLogger.With("component", name),
		bytecountFactory:    bf,
		ciliumEndpointStore: cepStore,
		svcRegistrar:        svcRegistrar,
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
	bf := s.bytecountFactory
	if bf == nil {
		return new(counterpb.Empty), util.ErrFactoryNotInited
	}
	cepStore := s.ciliumEndpointStore
	if cepStore == nil {
		return new(counterpb.Empty), util.ErrStoreNotInited
	}
	counter := in.GetCounter()
	eid := counter.GetEndpointId()
	dir := counter.GetDirection()
	cleanUp := in.GetCleanUp()
	if cleanUp {
		if err := cepStore.Remove(ctx, eid); err != nil {
			return new(counterpb.Empty), err
		}
	}
	var t bytecount.Counter
	switch dir {
	case counterpb.Direction_V4Ingress:
		t = bytecount.IPv4Ingress
	case counterpb.Direction_V4Egress:
		t = bytecount.IPv4Egress
	default:
		return new(counterpb.Empty), util.ErrUnknownDirection
	}
	if err := cepStore.Create(ctx, eid); err != nil {
		return nil, err
	}

	return new(counterpb.Empty), bf.CreateCounter(ctx, eid, t)
}

func (s *TrafficService) Subscribe(ctx context.Context, in *counterpb.SubscribeRequest) (*counterpb.Empty, error) {
	return new(counterpb.Empty), nil
}

func (s *TrafficService) Unsubscribe(ctx context.Context, in *counterpb.UnsubscribeRequest) (*counterpb.Empty, error) {
	return new(counterpb.Empty), nil
}

func (s *TrafficService) DumpTraffic(ctx context.Context, in *counterpb.DumpTrafficRequest) (*counterpb.DumpTrafficResponse, error) {
	return nil, nil
}
