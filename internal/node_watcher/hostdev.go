package node_watcher

import (
	"context"
	"errors"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"

	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	netlib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/net"
)

type HostDevWatcherParams struct {
	ParentLogger log.Logger
	netlib.NetLib
	modules.BPFTrafficFactory
	modules.Classifier
	conf.HostDevWatcherConfig
}

type HostDevWatcher struct {
	log.Logger
	HostDevWatcherParams
}

// TODO: monitor the change of host devices
func NewHostDevWatcher(params HostDevWatcherParams) (*HostDevWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("host_dev_watcher")
	if err != nil {
		return nil, err
	}
	return &HostDevWatcher{
		Logger:               logger,
		HostDevWatcherParams: params,
	}, nil
}

func (w *HostDevWatcher) Start(ctx context.Context) error {
	for _, hostDev := range w.HostDevs {
		addrs, err := w.AddrsByLinkName(hostDev)
		if errors.Is(err, netlib.ErrInterfaceNotExists) {
			w.Infof("this interface doesn't exist. ignore it")
			continue
		} else if err != nil {
			return err
		}
		for _, addr := range addrs {
			err := w.RegisterHostAddr(addr.String())
			if err != nil {
				return err
			}
		}
		if err := w.SubscribeToHostDev(hostDev); err != nil {
			return err
		}
	}
	return nil
}
