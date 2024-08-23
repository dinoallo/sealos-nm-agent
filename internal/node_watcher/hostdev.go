package node_watcher

import (
	"context"
	"errors"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"

	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	netlib "github.com/dinoallo/sealos-networkmanager-agent/pkg/net"
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
	hostNetnsEntry *NetnsEntry
	HostDevWatcherParams
}

// TODO: monitor the change of host devices
func NewHostDevWatcher(params HostDevWatcherParams) (*HostDevWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("host_dev_watcher")
	if err != nil {
		return nil, err
	}
	hostNetnsEntry, err := NewNetnsEntry("")
	if err != nil {
		return nil, err
	}
	return &HostDevWatcher{
		Logger:               logger,
		HostDevWatcherParams: params,
		hostNetnsEntry:       hostNetnsEntry,
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
		if err := w.updateHostDev(hostDev); err != nil {
			return err
		}
		w.Debugf("host dev %v watched", hostDev)
	}
	return nil
}

func (w *HostDevWatcher) updateHostDev(ifName string) error {
	e := w.hostNetnsEntry
	if err := e.installEgressFilterOnIf(ifName, egressFilterNameForHostDev, w.GetEgressFilterFDForHostDev()); err != nil {
		return err
	}
	return nil
}

func (w *HostDevWatcher) Close() {
	bpfHooker := w.hostNetnsEntry.Hooker
	doResettingHostDev := func(ifHash string, ifEntry *IfEntry) bool {
		if err := bpfHooker.FilterDel(ifEntry.EgressFilter); err != nil {
			w.Errorf("failed to remove egress filter for host device %v: %v", ifEntry.Name, err)
		} else {
			w.Debugf("successfully remove egress filter for host device %v: %v", ifEntry.Name, err)
		}
		return true
	}
	w.hostNetnsEntry.IfEntries.Range(doResettingHostDev)
}
