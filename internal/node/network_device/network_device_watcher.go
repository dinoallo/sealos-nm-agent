package network_device

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	errutil "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/errors/util"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	netlib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/net"
)

var (
	//TODO: check me
	excludedDevicePrefixes = map[string]struct{}{
		"cilium_":    {},
		"lo":         {},
		"docker":     {},
		"veth":       {},
		"lxc_health": {},
		"tailscale":  {},
		"kube":       {},
	}
	//TODO: make these configurable
	podDevicePrefixes = map[string]struct{}{
		"lxc": {},
	}
	hostDevicePrefixes = map[string]struct{}{
		"e": {},
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
	modules.BPFHostTrafficModule
	modules.BPFPodTrafficModule
	netlib.NetLib
}

type NetworkDeviceWatcher struct {
	logger  log.Logger
	devices *sync.Map
	NetworkDeviceWatcherParams
}

func NewNetworkDeviceWatcher(params NetworkDeviceWatcherParams) (*NetworkDeviceWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("pod_network_device_watcher")
	if err != nil {
		return nil, err
	}
	return &NetworkDeviceWatcher{
		logger:                     logger,
		devices:                    &sync.Map{},
		NetworkDeviceWatcherParams: params,
	}, nil
}

func (w *NetworkDeviceWatcher) Start(ctx context.Context) error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := w.updateDevices(ctx); err != nil {
					w.logger.Error(errutil.Err(ErrUpdateDevices, err))
					return
				}

				time.Sleep(w.SyncPeriod)
			}
		}
	}()
	return nil
}

func (w *NetworkDeviceWatcher) updateDevices(ctx context.Context) error {
	ifaces, err := w.Interfaces()
	if err != nil {
		return err
	}
	newIfaces := make(map[int]*net.Interface)
	for i := 0; i < len(ifaces); i++ {
		index := ifaces[i].Index
		newIfaces[index] = &ifaces[i]
	}
	// delete stale ifaces
	deleteIface := func(k, v any) bool {
		id, ok := k.(int)
		if !ok {
			w.logger.Error(ErrConvertKeyToIfaceIDFailed)
			return true
		}
		if _, ok := newIfaces[id]; !ok {
			w.devices.Delete(id)
		}
		return true
	}
	w.devices.Range(deleteIface)
	// add new ifaces
	for index, iface := range newIfaces {
		w.devices.LoadOrStore(index, iface)
		if !isViableDevices(iface.Name) {
			continue
		}
		if isPodDevice(iface.Name) {
			if err := w.BPFPodTrafficModule.SubscribeToDevice(iface.Name); err != nil {
				w.logger.Error(err)
				continue
			}
		}
		if isHostDevice(iface.Name) {
			if err := w.BPFHostTrafficModule.SubscribeToDevice(iface.Name); err != nil {
				w.logger.Error(err)
				continue
			}
		}
	}
	return nil
}

// this function is only used for testing
func (w *NetworkDeviceWatcher) dumpDeviceIndexes() []int {
	var indexes []int
	dumpDevice := func(key, value any) bool {
		dev, ok := value.(*net.Interface)
		if !ok {
			return true
		}
		indexes = append(indexes, dev.Index)
		return true
	}
	w.devices.Range(dumpDevice)
	return indexes
}

func isViableDevices(iface string) bool {
	for prefix := range excludedDevicePrefixes {
		if strings.HasPrefix(iface, prefix) {
			return false
		}
	}
	//TODO: ignore devices that masked by excludedFlags
	return true
}

func isPodDevice(iface string) bool {
	for prefix := range podDevicePrefixes {
		if strings.HasPrefix(iface, prefix) {
			return true
		}
	}
	return false
}

func isHostDevice(iface string) bool {
	for prefix := range hostDevicePrefixes {
		if strings.HasPrefix(iface, prefix) {
			return true
		}
	}
	return false
}
