package store

import (
	"net"

	"github.com/cilium/cilium/pkg/identity"
)

type TrafficDirection uint32

const (
	V4Ingress TrafficDirection = iota
	V4Egress
	V6Ingress
	V6Egress
)

type TrafficAccount struct {
	name      string
	ip        net.IP
	sentBytes uint32 // for cache
	recvBytes uint32 // for cache
}

type TrafficReport struct {
	Dir        TrafficDirection
	Protocol   uint32
	LocalIP    net.IP
	LocalPort  uint32
	RemoteIP   net.IP
	RemotePort uint32
	DataBytes  uint32
	Identity   identity.NumericIdentity
}
