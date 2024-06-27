package network_device

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/stretchr/testify/assert"
	loglib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	zaplog "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log/zap"
)

var (
	watchPeriod           = time.Second * 2
	globalLogger          loglib.Logger
	globalConfig          NetworkDeviceWatcherConfig
	dummyBPFTrafficModule = mock.NewDummyBPFTrafficModule()

	ignoredDevices = []string{
		"lxc_health",
		"cilium_host",
		"tailscale0",
		"wlan0",
	}
	podDevices = []string{
		"lxc9c9be1a12014@if10",
		"lxc0404f108f677@if16",
	}
	hostDevices = []string{
		"enp5s0",
		"ens18",
		"eth0",
	}

	nonPodDevices  = append(ignoredDevices, hostDevices...)
	nonHostDevices = append(ignoredDevices, podDevices...)
)

func setUpEnv(netlib *mock.TestingNetLib) (*NetworkDeviceWatcher, error) {
	params := NetworkDeviceWatcherParams{
		ParentLogger:               globalLogger,
		NetworkDeviceWatcherConfig: globalConfig,
		BPFTrafficFactory:          dummyBPFTrafficModule,
		NetLib:                     netlib,
	}
	w, err := NewNetworkDeviceWatcher(params)
	if err != nil {
		return nil, err
	}
	if err := w.Start(context.Background()); err != nil {
		return nil, err
	}
	return w, err
}

func TestDeviceChecking(t *testing.T) {
	w, err := setUpEnv(mock.NewTestingNetLib())
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	t.Run("these are pod devices", func(t *testing.T) {
		for _, dev := range podDevices {
			ok := w.isPodDevice(dev)
			assert.Truef(t, ok, "iface: %v", dev)
		}
	})
	t.Run("these are not pod devices", func(t *testing.T) {
		for _, dev := range nonPodDevices {
			ok := w.isPodDevice(dev)
			assert.Falsef(t, ok, "iface: %v", dev)
		}
	})
	t.Run("these are host devices", func(t *testing.T) {
		for _, dev := range hostDevices {
			ok := w.isHostDevice(dev)
			assert.Truef(t, ok, "iface: %v", dev)
		}
	})
	t.Run("these are not host devices", func(t *testing.T) {
		for _, dev := range nonHostDevices {
			ok := w.isHostDevice(dev)
			assert.Falsef(t, ok, "iface: %v", dev)
		}
	})
}

func TestDeviceWatching(t *testing.T) {
	netlib := mock.NewTestingNetLib()
	w, err := setUpEnv(netlib)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	t.Run("update the interfaces and wait for a while", func(t *testing.T) {
		err := netlib.Update()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		expectedDevices, err := netlib.GetInterfaceNames()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		t.Logf("device to watch: %+v", expectedDevices)
		time.Sleep(watchPeriod + time.Second*1)
	})
	t.Run("dump and check devices", func(t *testing.T) {
		actualDevices := w.dumpDevices()
		t.Logf("devices watched: %+v", actualDevices)
	})
	t.Run("update the interfaces and wait for a while", func(t *testing.T) {
		err := netlib.Update()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		expectedDevices, err := netlib.GetInterfaceNames()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		t.Logf("device to watch: %+v", expectedDevices)
		time.Sleep(watchPeriod + time.Second*1)
	})
	t.Run("dump and check devices", func(t *testing.T) {
		actualDevices := w.dumpDevices()
		t.Logf("devices watched: %+v", actualDevices)
	})
}

func TestMain(m *testing.M) {
	var err error
	globalLogger, err = zaplog.NewZap(true)
	if err != nil {
		log.Printf("failed to initialize logger: %v", err)
		return
	}
	globalConfig = NetworkDeviceWatcherConfig{
		WatchPeriod: watchPeriod,
	}
	m.Run()
}
