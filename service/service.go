package service

import (
	"context"
	"net"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

const (
	DEFAULT_SERVICE_PORT = "50051"
)

type ServiceManager struct {
	svcRegistrar *grpc.Server
	logger       *zap.SugaredLogger
}

func (m *ServiceManager) NewServiceManager(pl *zap.SugaredLogger) (*ServiceManager, error) {
	svcRegistrar := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 10 * time.Second, // TODO: validate me
		}),
	)
	reflection.Register(svcRegistrar)
	return &ServiceManager{
		svcRegistrar: svcRegistrar,
		logger:       pl.With("component", "service_manager"),
	}, nil
}

func (m *ServiceManager) Launch(ctx context.Context, eg *errgroup.Group) error {
	// init service here
	if ts, err := NewTrafficService(m.logger, bf, cepStore); err != nil {
		return err
	} else {
		ts.register(m.svcRegistrar)
	}
	//TODO: gracefully stop
	eg.Go(
		func() error {
			if lis, err := net.Listen("tcp", DEFAULT_SERVICE_PORT); err != nil {
				// m.logger.Infof("failed to listen: %v", err)
				return err
			} else {
				if err := m.svcRegistrar.Serve(lis); err != nil {
					// m.logger.Infof("failed to serve: %v", err)
					return err
				}
			}
			return nil
		})
	return nil
}

func (m *ServiceManager) GetName() string {
	return "service"
}
