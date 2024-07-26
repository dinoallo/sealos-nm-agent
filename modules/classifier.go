package modules

import (
	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	taglib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/tag"
)

type Classifier interface {
	RegisterPod(addr string, podMeta structs.PodMeta) error
	UnregisterPod(addr string) error
	RegisterExposedPort(podAddr string, podPort uint32) error
	UnregisterExposedPort(podAddr string, podPort uint32) error
	RegisterNodePort(podAddr string, podPort uint32) error
	UnregisterNodePort(podAddr string, podPort uint32) error
	RegisterHostAddr(hostAddr string) error
	UnregisterHostAddr(hostAddr string) error
	GetPodMeta(addr string) (structs.PodMeta, bool)
	IsPodAddr(addr string) (bool, error)
	IsHostAddr(addr string) (bool, error)
	IsSkippedAddr(addr string) (bool, error)
	IsNodeAddr(addr string) (bool, error)
	IsWorldAddr(addr string) (bool, error)
	IsPortExposed(podAddr string, podPort uint32) (bool, error)
	IsPortNodePort(podAddr string, podPort uint32) (bool, error)
	GetAddrType(addr string) (AddrType, error)
}

type Tagger struct {
	Tag         taglib.Tag
	TaggingFunc func(structs.RawTrafficMetaData) bool
}

type AddrType uint32

const (
	AddrTypeUnknown AddrType = iota
	AddrTypePod
	AddrTypeSkipped
	AddrTypeHost
	AddrTypeNode
	AddrTypePrivate
	AddrTypeWorld
)

func (t AddrType) String() string {
	switch t {
	case AddrTypePod:
		return "pod"
	case AddrTypeSkipped:
		return "skipped"
	case AddrTypeHost:
		return "host"
	case AddrTypeNode:
		return "node"
	case AddrTypePrivate:
		return "private"
	case AddrTypeWorld:
		return "world"
	default:
		return "unknown"
	}
}
