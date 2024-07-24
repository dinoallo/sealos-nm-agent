package traffic

import (
	"encoding/binary"
	"unsafe"

	structsapi "github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	netutil "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/net/util"
	"golang.org/x/sys/unix"
)

type trafficEventKind uint32

const (
	Ingress trafficEventKind = iota
	Egress
)

var (
	v4Proto = uint32(htons(unix.ETH_P_IP))
	v6Proto = uint32(htons(unix.ETH_P_IPV6))
)

// this struct matches the event_t struct in c source code
type trafficEventT struct {
	Protocol   uint32
	Len        uint32
	Family     uint32
	SkProtocol uint32
	DstIp4     uint32
	SrcIp4     uint32
	DstIp6     [4]uint32
	SrcIp6     [4]uint32
	SrcPort    uint32
	DstPort    uint16
	_          [2]byte
	Identity   uint32
}

func (_event *trafficEventT) convertToRawTraffic() structsapi.RawTraffic {
	e := structsapi.RawTraffic{
		Meta: structsapi.RawTrafficMetaData{
			Protocol: _event.Protocol,
			Family:   _event.Family,
		},
		DataBytes: _event.Len, //TODO: maybe use bpf timesetamp?
	}
	// handle ipv4 and ipv6
	var srcIP string
	var dstIP string
	if _event.Protocol == v4Proto {
		if _srcIP, ok := netutil.ToIP(_event.SrcIp4, nil, 4); ok {
			srcIP = _srcIP.String()
		}
		if _dstIP, ok := netutil.ToIP(_event.DstIp4, nil, 4); ok {
			dstIP = _dstIP.String()
		}
	} else if _event.Protocol == v6Proto {
		if _srcIP, ok := netutil.ToIP(0, _event.SrcIp6[:], 6); ok {
			srcIP = _srcIP.String()
		}
		if _dstIP, ok := netutil.ToIP(0, _event.DstIp6[:], 6); ok {
			dstIP = _dstIP.String()
		}
	} else {
		return e
	}
	e.Meta.Src.IP = srcIP
	e.Meta.Dst.IP = dstIP
	e.Meta.Src.Port = _event.SrcPort
	e.Meta.Dst.Port = uint32(_event.DstPort)
	return e
}

type notificationT struct {
	Error uint32
}

// func (_event *trafficEventT) convertToRawTrafficEvent() structs.RawTrafficEvent {
// 	//TODO: check ipv6
// 	e := structs.RawTrafficEvent{
// 		RawTrafficEventMeta: structs.RawTrafficEventMetaData{
// 			Protocol: _event.Protocol,
// 			Family:   _event.Family,
// 			// Identity: identity.NumericIdentity(_event.Identity),
// 		},
// 		// ID:        id, //TODO: generate id
// 		DataBytes: _event.Len,
// 		Timestamp: time.Now(), //TODO: maybe use bpf timestamp?
// 	}
// 	// handle ipv4 and ipv6
// 	var srcIP string
// 	var dstIP string
// 	if _event.Protocol == v4Proto {
// 		if _srcIP, ok := netutil.ToIP(_event.SrcIp4, nil, 4); ok {
// 			srcIP = _srcIP.String()
// 		}
// 		if _dstIP, ok := netutil.ToIP(_event.DstIp4, nil, 4); ok {
// 			dstIP = _dstIP.String()
// 		}
// 	} else if _event.Protocol == v6Proto {
// 		if _srcIP, ok := netutil.ToIP(0, _event.SrcIp6[:], 6); ok {
// 			srcIP = _srcIP.String()
// 		}
// 		if _dstIP, ok := netutil.ToIP(0, _event.DstIp6[:], 6); ok {
// 			dstIP = _dstIP.String()
// 		}
// 	} else {
// 		return e
// 	}
// 	e.RawTrafficEventMeta.SrcIP = srcIP
// 	e.RawTrafficEventMeta.DstIP = dstIP
// 	e.RawTrafficEventMeta.SrcPort = _event.SrcPort
// 	e.RawTrafficEventMeta.DstPort = uint32(_event.DstPort)
// 	return e
// }

// https://github.com/chamaken/cgolmnl/blob/728c8fce1cb5d8ee97851dc9bd553c95515eb0b0/inet/inet.go#L28
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
