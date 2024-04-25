package common

type TCDirection uint32
type TrafficDirection uint32

const (
	BPFFSRoot = "/sys/fs/bpf"

	TRAFFIC_DIR_UNKNOWN TrafficDirection = iota
	TRAFFIC_DIR_V4_INGRESS
	TRAFFIC_DIR_V4_EGRESS
	TRAFFIC_DIR_V6_INGRESS
	TRAFFIC_DIR_V6_EGRESS

	TC_DIR_UNKNOWN TCDirection = iota
	TC_DIR_INGRESS
	TC_DIR_EGRESS
)
