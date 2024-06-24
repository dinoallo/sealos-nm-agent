package network_device

import (
	"context"
	"regexp"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/puzpuzpuz/xsync"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	netlib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/net"
)

var (
	//TODO: make these configurable
	podDeviceRegexes = map[string]struct{}{
		"^lxc[a-z0-9]": {},
	}
	hostDeviceRegexes = map[string]struct{}{
		"^(eth|ens|enp|eno)": {},
	}
)

type NetworkDeviceWatcherConfig struct {
	SyncPeriod time.Duration
}

func NewNetworkDeviceWatcherConfig() NetworkDeviceWatcherConfig {
	return NetworkDeviceWatcherConfig{
		SyncPeriod: 10 * time.Second,
	}
}

type NetworkDeviceWatcherParams struct {
	ParentLogger log.Logger
	NetworkDeviceWatcherConfig
	modules.BPFTrafficFactory
	netlib.NetLib
}

type actionKind int
type ifaceKind int

const (
	actionSubscribe actionKind = iota
	actionUnsubscribe

	ifaceTypePod ifaceKind = iota
	ifaceTypeHost
)

type DevMsg struct {
	ifaceName string
	ifaceType ifaceKind
	action    actionKind
}

type NetworkDeviceWatcher struct {
	log.Logger
	deviceToSync  chan DevMsg
	deviceWatched *xsync.MapOf[string, ifaceKind]
	NetworkDeviceWatcherParams
}

func NewNetworkDeviceWatcher(params NetworkDeviceWatcherParams) (*NetworkDeviceWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("network_device_watcher")
	if err != nil {
		return nil, err
	}
	return &NetworkDeviceWatcher{
		Logger:                     logger,
		NetworkDeviceWatcherParams: params,
		deviceToSync:               make(chan DevMsg),
		deviceWatched:              xsync.NewMapOf[ifaceKind](),
	}, nil
}

func (w *NetworkDeviceWatcher) Start(ctx context.Context) error {
	go func() {
		for {
			if err := w.watch(ctx); err != nil {
				w.Error(err)
				return
			}
			time.Sleep(w.SyncPeriod)
		}
	}()
	go func() {
		for {
			if err := w.sync(ctx); err != nil {
				w.Error(err)
			}
		}
	}()
	return nil
}

func (w *NetworkDeviceWatcher) sync(ctx context.Context) error {
	var msg DevMsg
	select {
	case <-ctx.Done():
	case msg = <-w.deviceToSync:
	}
	var err error
	ifaceName := msg.ifaceName
	if msg.action == actionSubscribe && msg.ifaceType == ifaceTypePod {
		err = w.SubscribeToPodDevice(ifaceName)
	} else if msg.action == actionSubscribe && msg.ifaceType == ifaceTypeHost {
		err = w.SubscribeToHostDevice(ifaceName)
	} else if msg.action == actionUnsubscribe && msg.ifaceType == ifaceTypePod {
		err = w.UnsubscribeFromPodDevice(ifaceName)
	} else if msg.action == actionUnsubscribe && msg.ifaceType == ifaceTypeHost {
		err = w.UnsubscribeFromHostDevice(ifaceName)
	}
	if err != nil && err != modules.ErrDeviceNotFound {
		select {
		case <-ctx.Done():
		case w.deviceToSync <- msg:
		}
	}
	return err
}

func (w *NetworkDeviceWatcher) watch(ctx context.Context) error {
	ifaces, err := w.Interfaces()
	if err != nil {
		return err
	}
	newIfaces := make(map[string]ifaceKind)
	for _, iface := range ifaces {
		if w.isPodDevice(iface.Name) {
			newIfaces[iface.Name] = ifaceTypePod
		} else if w.isHostDevice(iface.Name) {
			newIfaces[iface.Name] = ifaceTypeHost
		}
	}
	deleteStaleIface := func(ifaceName string, ifaceType ifaceKind) bool {
		if _, ok := newIfaces[ifaceName]; !ok {
			UnsubMsg := DevMsg{
				ifaceName: ifaceName,
				ifaceType: ifaceType,
				action:    actionUnsubscribe,
			}
			select {
			case <-ctx.Done():
			case w.deviceToSync <- UnsubMsg:
				w.deviceWatched.Delete(ifaceName)
			}
		}
		return true
	}
	w.deviceWatched.Range(deleteStaleIface)

	for ifaceName, ifaceType := range newIfaces {
		if _, loaded := w.deviceWatched.Load(ifaceName); loaded {
			continue
		}
		msg := DevMsg{
			ifaceName: ifaceName,
			ifaceType: ifaceType,
			action:    actionSubscribe,
		}
		select {
		case <-ctx.Done():
		case w.deviceToSync <- msg:
			w.deviceWatched.Store(ifaceName, ifaceType)
		}
	}
	return nil
}

func (w *NetworkDeviceWatcher) isPodDevice(iface string) bool {
	for regex := range podDeviceRegexes {
		matched, err := regexp.MatchString(regex, iface)
		if err != nil {
			w.Errorf("failed to check if %v is a pod device with regex %v ignore this check: %v", iface, regex, err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

func (w *NetworkDeviceWatcher) isHostDevice(iface string) bool {
	for regex := range hostDeviceRegexes {
		matched, err := regexp.MatchString(regex, iface)
		if err != nil {
			w.Errorf("failed to check if %v is a host device with regex %v ignore this check: %v", iface, regex, err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

func (w *NetworkDeviceWatcher) dumpDevices() []string {
	var devices []string
	dump := func(ifaceName string, ifaceType ifaceKind) bool {
		devices = append(devices, ifaceName)
		return true
	}
	w.deviceWatched.Range(dump)
	return devices
}
