package mock

import (
	"math/rand"
	"net"
	"sync"
)

var (
	deviceSet = []string{
		"eth42",
		"eth24",
		"ens42",
		"ens24",
		"lxc42",
		"lxc24",
		"dummy42",
		"dummy24",
		"veth42",
		"veth24",
		"docker0",
		"cilium_host",
		"lo",
	}
)

type TestingNetLib struct {
	interfaces  []net.Interface
	interfaceMu sync.RWMutex
}

func NewTestingNetLib() *TestingNetLib {
	return &TestingNetLib{
		interfaces:  randInterfaces(),
		interfaceMu: sync.RWMutex{},
	}
}

func randInterfaces() []net.Interface {
	var interfaces []net.Interface
	upperbound := len(deviceSet)
	for {
		if upperbound <= 0 {
			break
		}
		i := rand.Intn(upperbound)
		iface := net.Interface{
			Index: i,
			Name:  deviceSet[i],
		}
		interfaces = append(interfaces, iface)
		upperbound = i
	}
	return interfaces
}

func (m *TestingNetLib) Interfaces() ([]net.Interface, error) {
	m.interfaceMu.RLock()
	defer m.interfaceMu.RUnlock()
	interfacesCopy := make([]net.Interface, len(m.interfaces))
	copy(interfacesCopy, m.interfaces)
	return interfacesCopy, nil
}

func (m *TestingNetLib) GetInterfaceIndexes() ([]int, error) {
	var indexes []int
	ifaces, err := m.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		indexes = append(indexes, iface.Index)
	}
	return indexes, nil
}
func (m *TestingNetLib) Update() error {
	interfaces := randInterfaces()
	m.interfaceMu.Lock()
	defer m.interfaceMu.Unlock()
	m.interfaces = interfaces
	return nil
}
