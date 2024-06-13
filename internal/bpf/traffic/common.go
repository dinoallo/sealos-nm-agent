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

func (_event *host_trafficEventT) convertToRawTrafficEvent() structs.RawTrafficEvent {
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

func (_event *pod_trafficEventT) convertToRawTrafficEvent() structs.RawTrafficEvent {
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
