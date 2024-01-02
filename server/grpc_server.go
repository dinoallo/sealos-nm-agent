package server

import (
	"context"
	"fmt"

	"github.com/dinoallo/sealos-networkmanager-agent/bpf/bytecount"
	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto/agent"
	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"go.uber.org/zap"
)

type GRPCServer struct {
	counterpb.UnimplementedCountingServiceServer
	logger              *zap.SugaredLogger
	bytecountFactory    *bytecount.Factory
	trafficAccountStore *store.TrafficAccountStore
	ciliumEndpointStore *store.CiliumEndpointStore
}

func NewServer(baseLogger *zap.SugaredLogger, bf *bytecount.Factory, taStore *store.TrafficAccountStore, cepStore *store.CiliumEndpointStore) (*GRPCServer, error) {
	if baseLogger == nil || bf == nil {
		return nil, fmt.Errorf("both the base logger and the factory shouldn't be nil")
	}
	return &GRPCServer{
		logger:              baseLogger,
		bytecountFactory:    bf,
		trafficAccountStore: taStore,
		ciliumEndpointStore: cepStore,
	}, nil
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
	taStore := s.trafficAccountStore
	if taStore == nil {
		return new(counterpb.Empty), util.ErrStoreNotInited
	}
	counter := in.GetCounter()
	eid := counter.GetEndpointId()
	dir := counter.GetDirection()
	ipAddrs := counter.GetIpAddrs()
	cleanUp := in.GetCleanUp()
	if cleanUp {
		if err := cepStore.Remove(ctx, eid); err != nil {
			return new(counterpb.Empty), err
		}
		for _, ipAddr := range ipAddrs {
			if err := taStore.DeleteTrafficAccount(ctx, ipAddr); err != nil {
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
	if in == nil {
		return nil, util.ErrRequestNotPassed
	}
	taStore := s.trafficAccountStore
	if taStore == nil {
		return nil, util.ErrStoreNotInited
	}
	addr := in.GetAddress()
	tag := in.GetTag()
	reset := in.GetReset_()
	if p, err := taStore.DumpTraffic(ctx, addr, tag, reset); err != nil {
		return nil, err
	} else {
		dtr := counterpb.DumpTrafficResponse{
			SentBytes: p.SentBytes,
			RecvBytes: p.RecvBytes,
		}
		return &dtr, nil
	}
}
