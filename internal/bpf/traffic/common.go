package traffic

import (
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	netutil "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/net/util"
	"golang.org/x/sys/unix"
)

type trafficEventKind uint32

const (
	Ingress trafficEventKind = iota
	Egress
)

// this struct matches the event_t struct in c source code
type trafficEventT struct {
	Len      uint32
	Family   uint32
	Protocol uint32
	DstIp4   uint32
	SrcIp4   uint32
	DstIp6   [4]uint32
	SrcIp6   [4]uint32
	SrcPort  uint32
	DstPort  uint16
	_        [2]byte
	Identity uint32
}

func (_event *trafficEventT) convertToRawTrafficEvent() structs.RawTrafficEvent {
	//TODO: check ipv6
	e := structs.RawTrafficEvent{
		RawTrafficEventMeta: structs.RawTrafficEventMetaData{
			Protocol: _event.Protocol,
			Family:   _event.Family,
			// Identity: identity.NumericIdentity(_event.Identity),
		},
		// ID:        id, //TODO: generate id
		DataBytes: _event.Len,
		Timestamp: time.Now(), //TODO: maybe use bpf timestamp?
	}
	// handle ipv4 and ipv6
	var srcIP string
	var dstIP string
	if _event.Family == unix.AF_INET {
		if _srcIP, ok := netutil.ToIP(_event.SrcIp4, nil, 4); ok {
			srcIP = _srcIP.String()
		}
		if _dstIP, ok := netutil.ToIP(_event.DstIp4, nil, 4); ok {
			dstIP = _dstIP.String()
		}
	} else if _event.Family == unix.AF_INET6 {
		if _srcIP, ok := netutil.ToIP(0, _event.SrcIp6[:], 6); ok {
			srcIP = _srcIP.String()
		}
		if _dstIP, ok := netutil.ToIP(0, _event.SrcIp6[:], 6); ok {
			dstIP = _dstIP.String()
		}
	} else {
		return e
	}
	e.RawTrafficEventMeta.SrcIP = srcIP
	e.RawTrafficEventMeta.DstIP = dstIP
	e.RawTrafficEventMeta.SrcPort = _event.SrcPort
	e.RawTrafficEventMeta.DstPort = uint32(_event.DstPort)
	return e
}
