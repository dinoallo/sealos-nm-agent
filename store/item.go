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

type Property struct {
	SentBytes uint64
	RecvBytes uint64
}

type TrafficAccount struct {
	IP         string `bson:"ip"`
	Properties map[string]Property
}

type TrafficReport struct {
	Dir       TrafficDirection
	Protocol  uint32
	SrcIP     net.IP
	SrcPort   uint32
	DstIP     net.IP
	DstPort   uint32
	DataBytes uint32
	Identity  identity.NumericIdentity
}
