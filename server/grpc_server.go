package server

import (
	"context"
	"fmt"
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

type GRPCServer struct {
	counterpb.UnimplementedCountingServiceServer
	logger              *zap.SugaredLogger
	bytecountFactory    *bytecount.Factory
	ciliumEndpointStore *store.CiliumEndpointStore
}

func NewServer(baseLogger *zap.SugaredLogger, bf *bytecount.Factory, cepStore *store.CiliumEndpointStore) (*GRPCServer, error) {
	if baseLogger == nil || bf == nil {
		return nil, fmt.Errorf("both the base logger and the factory shouldn't be nil")
	}
	return &GRPCServer{
		logger:              baseLogger,
		bytecountFactory:    bf,
		ciliumEndpointStore: cepStore,
	}, nil
}

func (s *GRPCServer) Launch(ctx context.Context, eg *errgroup.Group) error {
	svcRegistrar := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 10 * time.Second, // TODO: validate me
		}),
	)
	counterpb.RegisterCountingServiceServer(svcRegistrar, svc)
	return nil
}

func (s *GRPCServer) GetName() string {
	return "grpc_server"
}

func (s *GRPCServer) CreateCounter(ctx context.Context, in *counterpb.CreateCounterRequest) (*counterpb.Empty, error) {
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

func (s *GRPCServer) Subscribe(ctx context.Context, in *counterpb.SubscribeRequest) (*counterpb.Empty, error) {
	return new(counterpb.Empty), nil
}

func (s *GRPCServer) Unsubscribe(ctx context.Context, in *counterpb.UnsubscribeRequest) (*counterpb.Empty, error) {
	return new(counterpb.Empty), nil
}

func (s *GRPCServer) DumpTraffic(ctx context.Context, in *counterpb.DumpTrafficRequest) (*counterpb.DumpTrafficResponse, error) {
	return nil, nil
}
