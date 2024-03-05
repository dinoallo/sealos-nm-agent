package consts

type TrafficDirection uint32

const (
	TRAFFIC_DIR_UNKNOWN TrafficDirection = iota
	TRAFFIC_DIR_V4_INGRESS
	TRAFFIC_DIR_V4_EGRESS
	TRAFFIC_DIR_V6_INGRESS
	TRAFFIC_DIR_V6_EGRESS
)
