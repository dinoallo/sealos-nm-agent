package mock

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

const (
	suffixCharset = "abcdefghijklmnopqrstuvwxyz" + "0123456789"
)

var (
	deviceSet = []string{
		"eth42",
		"ens42",
		"enp5s0",
		"wlan0",
		"lxc42",
		"lxc_health",
		"dummy42",
		"veth42",
		"docker0",
		"cilium_host",
		"lo",
	}

	seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
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

func (m *TestingNetLib) GetInterfaceNames() ([]string, error) {
	var names []string
	ifaces, err := m.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	return names, nil
}

func (m *TestingNetLib) Update() error {
	interfaces := randInterfaces()
	m.interfaceMu.Lock()
	defer m.interfaceMu.Unlock()
	m.interfaces = interfaces
	return nil
}

func generateRandomIface(prefix string) string {
	suffix := generateRandomSuffix(8)
	return prefix + suffix
}

func generateRandomSuffix(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = suffixCharset[seededRand.Intn(len(suffixCharset))]
	}
	return string(b)
}
