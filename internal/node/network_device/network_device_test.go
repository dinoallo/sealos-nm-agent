package network_device

import (
	"context"
	"log"
	"sort"
	"testing"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/stretchr/testify/assert"
	loglib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	zaplog "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log/zap"
)

var (
	syncPeriod            = time.Second * 2
	globalLogger          loglib.Logger
	globalConfig          NetworkDeviceWatcherConfig
	dummyBPFTrafficModule = mock.NewDummyBPFTrafficModule()
)

func setUpEnv(netlib *mock.TestingNetLib) (*NetworkDeviceWatcher, error) {
	params := NetworkDeviceWatcherParams{
		ParentLogger:               globalLogger,
		NetworkDeviceWatcherConfig: globalConfig,
		BPFPodTrafficModule:        dummyBPFTrafficModule,
		BPFHostTrafficModule:       dummyBPFTrafficModule,
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
	_, err := setUpEnv(mock.NewTestingNetLib())
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	viableDevices := []string{
		"eth0",
		"ens4",
		"lxc42",
	}
	nonViableDevices := []string{
		"cilium_host",
		"docker0",
		"lo",
		"veth0",
	}
	t.Run("check viable devices", func(t *testing.T) {
		for _, dev := range viableDevices {
			t.Logf("device name: %v", dev)
			viable := isViableDevices(dev)
			assert.Equal(t, true, viable)
		}
	})
	t.Run("check not viable devices", func(t *testing.T) {
		for _, dev := range nonViableDevices {
			t.Logf("device name: %v", dev)
			viable := isViableDevices(dev)
			assert.Equal(t, false, viable)
		}
	})
}

// please run this test when the devices on the host don't constantly change
func TestDeviceUpdating(t *testing.T) {
	netlib := mock.NewTestingNetLib()
	w, err := setUpEnv(netlib)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	var expectedIndexes []int
	t.Run("update the interfaces and wait for a while", func(t *testing.T) {
		err := netlib.Update()
		assert.NoError(t, err)
		expectedIndexes, err = netlib.GetInterfaceIndexes()
		assert.NoError(t, err)
		time.Sleep(syncPeriod + time.Second*1)
	})
	t.Run("dump and check devices", func(t *testing.T) {
		actualIndexes := w.dumpDeviceIndexes()
		sort.Ints(expectedIndexes)
		t.Logf("expected indexes: %v", expectedIndexes)
		sort.Ints(actualIndexes)
		t.Logf("actual indexes: %v", actualIndexes)
		assert.Equal(t, expectedIndexes, actualIndexes)
	})
	t.Run("update the interfaces and wait for a while", func(t *testing.T) {
		err := netlib.Update()
		assert.NoError(t, err)
		expectedIndexes, err = netlib.GetInterfaceIndexes()
		assert.NoError(t, err)
		time.Sleep(syncPeriod + time.Second*1)
	})
	t.Run("dump and check devices", func(t *testing.T) {
		actualIndexes := w.dumpDeviceIndexes()
		sort.Ints(expectedIndexes)
		t.Logf("expected indexes: %v", expectedIndexes)
		sort.Ints(actualIndexes)
		t.Logf("actual indexes: %v", actualIndexes)
		assert.Equal(t, expectedIndexes, actualIndexes)
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
		SyncPeriod: syncPeriod,
	}
	m.Run()
}
