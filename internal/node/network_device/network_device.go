package network_device

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	errutil "github.com/dinoallo/sealos-networkmanager-agent/pkg/errors/util"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	netlib "github.com/dinoallo/sealos-networkmanager-agent/pkg/net"
	"golang.org/x/sys/unix"
)

var (
	//TODO: check me
	excludedDevicePrefixes = map[string]struct{}{
		"cilium_": {},
		"lo":      {},
		"docker":  {},
		// "cni":     {},
		"veth": {},
	}

	excludedIfFlagsMask uint32 = unix.IFF_SLAVE | unix.IFF_LOOPBACK
)

type NetworkDeviceWatcherConfig struct {
	SyncPeriod  time.Duration
	TestingMode bool
}

type NetworkDeviceWatcherParams struct {
	ParentLogger log.Logger
	NetworkDeviceWatcherConfig
	modules.BPFTrafficModule
	netlib.NetLib
}

type NetworkDeviceWatcher struct {
	logger  log.Logger
	devices *sync.Map
	NetworkDeviceWatcherParams
}

func NewNetworkDeviceWatcher(params NetworkDeviceWatcherParams) (*NetworkDeviceWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("network_device_watcher")
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
		if w.isViableDevices(iface.Name) {
			if err := w.SubscribeToDevice(iface.Name); err != nil {
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

func (w *NetworkDeviceWatcher) isViableDevices(iface string) bool {
	for prefix := range excludedDevicePrefixes {
		if strings.HasPrefix(iface, prefix) {
			return false
		}
	}
	//TODO: ignore devices that masked by excludedFlags
	return true
}
