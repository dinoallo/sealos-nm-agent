package mock

import (
	"log"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
)

type DummyClassifierConfig struct {
	PodAddr     string
	HostAddr    string
	WorldAddr   string
	NodeAddr    string
	SkippedAddr string
	PodPort     uint32 // only useful if PodAddr is set
}

type DummyClassifier struct {
	DummyClassifierConfig
}

func NewDummyClassifier(cfg DummyClassifierConfig) *DummyClassifier {
	return &DummyClassifier{
		DummyClassifierConfig: cfg,
	}
}

func (c *DummyClassifier) RegisterPod(addr string, podMeta structs.PodMeta) error {
	if addr != c.PodAddr {
		return nil
	}
	log.Printf("register pod %v/%v; addr: %v", podMeta.Namespace, podMeta.Name, addr)
	return nil
}

func (c *DummyClassifier) UnregisterPod(addr string) error {
	if addr != c.PodAddr {
		return nil
	}
	log.Printf("unregister pod addr: %v", addr)
	return nil
}

func (c *DummyClassifier) RegisterExposedPort(podAddr string, podPort uint32) error {
	if podAddr != c.PodAddr {
		return nil
	}
	if c.PodPort != 0 && podPort != c.PodPort {
		return nil
	}
	log.Printf("register exposed port %v for addr %v", podPort, podAddr)
	return nil
}

func (c *DummyClassifier) UnregisterExposedPort(podAddr string, podPort uint32) error {
	if podAddr != c.PodAddr {
		return nil
	}
	if c.PodPort != 0 && podPort != c.PodPort {
		return nil
	}
	log.Printf("unregister exposed port %v for addr %v", podPort, podAddr)
	return nil
}

func (c *DummyClassifier) RegisterNodePort(podAddr string, podPort uint32) error {
	if podAddr != c.PodAddr {
		return nil
	}
	if c.PodPort != 0 && podPort != c.PodPort {
		return nil
	}
	log.Printf("register node port %v for addr %v", podPort, podAddr)
	return nil
}

func (c *DummyClassifier) UnregisterNodePort(podAddr string, podPort uint32) error {
	if podAddr != c.PodAddr {
		return nil
	}
	if c.PodPort != 0 && podPort != c.PodPort {
		return nil
	}
	log.Printf("unregister exposed port %v for addr %v", podPort, podAddr)
	return nil
}

func (c *DummyClassifier) RegisterHostAddr(hostAddr string) error {
	if hostAddr != c.HostAddr {
		return nil
	}
	log.Printf("register host addr %v", hostAddr)
	return nil
}

func (c *DummyClassifier) UnregisterHostAddr(hostAddr string) error {
	if hostAddr != c.HostAddr {
		return nil
	}
	log.Printf("unregister host addr %v", hostAddr)
	return nil
}

func (c *DummyClassifier) GetPodMeta(addr string) (structs.PodMeta, bool) {
	return structs.PodMeta{}, false
}

func (c *DummyClassifier) IsPodAddr(addr string) (bool, error) {
	if addr == c.PodAddr {
		return true, nil
	}
	return false, nil
}

func (c *DummyClassifier) IsHostAddr(addr string) (bool, error) {
	if addr == c.HostAddr {
		return true, nil
	}
	return false, nil
}

func (c *DummyClassifier) IsSkippedAddr(addr string) (bool, error) {
	if addr == c.SkippedAddr {
		return true, nil
	}
	return false, nil
}

func (c *DummyClassifier) IsNodeAddr(addr string) (bool, error) {
	if addr == c.NodeAddr {
		return true, nil
	}
	return false, nil
}

func (c *DummyClassifier) IsWorldAddr(addr string) (bool, error) {
	if addr == c.WorldAddr {
		return true, nil
	}
	return false, nil
}

func (c *DummyClassifier) IsPortExposed(podAddr string, podPort uint32) (bool, error) {
	if podAddr == c.PodAddr && podPort == c.PodPort {
		return true, nil
	}
	return false, nil
}

func (c *DummyClassifier) IsPortNodePort(podAddr string, podPort uint32) (bool, error) {
	if podAddr == c.PodAddr && podPort == c.PodPort {
		return true, nil
	}
	return false, nil
}

func (c *DummyClassifier) GetAddrType(addr string) (modules.AddrType, error) {
	if addr == c.PodAddr {
		return modules.AddrTypePod, nil
	} else if addr == c.HostAddr {
		return modules.AddrTypeHost, nil
	} else if addr == c.WorldAddr {
		return modules.AddrTypeWorld, nil
	} else {
		return modules.AddrTypeUnknown, nil
	}
}
