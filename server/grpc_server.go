package server

import (
	"context"
	"fmt"

	"github.com/dinoallo/sealos-networkmanager-agent/bpf/bytecount"
	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
)

type GRPCServer struct {
	counterpb.UnimplementedCountingServiceServer
	logger           *zap.SugaredLogger
	bytecountFactory *bytecount.Factory
}

func NewServer(baseLogger *zap.SugaredLogger, bf *bytecount.Factory) (*GRPCServer, error) {
	if baseLogger == nil || bf == nil {
		return nil, fmt.Errorf("both the base logger and the factory shouldn't be nil")
	}
	return &GRPCServer{
		logger:           baseLogger,
		bytecountFactory: bf,
	}, nil
}

func (s *GRPCServer) CreateCounter(ctx context.Context, in *counterpb.CreateCounterRequest) (*counterpb.Empty, error) {
	counter := in.GetCounter()
	eid := counter.GetEndpointId()
	dir := counter.GetDirection()
	ipAddrs := counter.GetIpAddrs()
	cleanUp := in.GetCleanUp()
	bf := s.bytecountFactory
	if cleanUp {
		for _, ipAddr := range ipAddrs {
			if err := bf.CleanUp(ctx, ipAddr); err != nil {
				return new(counterpb.Empty), err
			}
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
	// log := s.logger.With(zap.Int64("endpoint", eid), zap.String("type", t.TypeStr))
	// log.Debugf("receive create counter request")
	return new(counterpb.Empty), bf.CreateCounter(ctx, eid, t)
}

func (s *GRPCServer) Subscribe(ctx context.Context, in *counterpb.SubscribeRequest) (*counterpb.Empty, error) {
	addr := in.GetAddress()
	port := in.GetPort()
	bf := s.bytecountFactory
	return new(counterpb.Empty), bf.Subscribe(ctx, addr, port)
}
