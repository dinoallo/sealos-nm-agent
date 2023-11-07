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
	eid := in.GetEndpointId()
	dir := in.GetDirection()
	bf := s.bytecountFactory
	var t bytecount.Counter
	switch dir {
	case counterpb.Direction_V4Ingress:
		t = bytecount.IPv4Ingress
	case counterpb.Direction_V4Egress:
		t = bytecount.IPv4Egress
	default:
		return new(counterpb.Empty), util.ErrUnknownDirection
	}
	log := s.logger.With(zap.Int64("endpoint", eid), zap.String("type", t.TypeStr))
	log.Debugf("receive create counter request")
	return new(counterpb.Empty), bf.CreateCounter(ctx, eid, t)
}

func (s *GRPCServer) RemoveCounter(ctx context.Context, in *counterpb.RemoveCounterRequest) (*counterpb.Empty, error) {
	eid := in.GetEndpointId()
	dir := in.GetDirection()
	bf := s.bytecountFactory
	var c bytecount.Counter
	switch dir {
	case counterpb.Direction_V4Ingress:
		c = bytecount.IPv4Ingress
	case counterpb.Direction_V4Egress:
		c = bytecount.IPv4Egress
	default:
		return new(counterpb.Empty), util.ErrUnknownDirection
	}
	log := s.logger.With(zap.Int64("endpoint", eid), zap.String("type", c.TypeStr))
	log.Debugf("receive remove counter request")
	return new(counterpb.Empty), bf.RemoveCounter(ctx, eid, c)
}
