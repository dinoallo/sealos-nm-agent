package util

import (
	"fmt"
	"math/rand"
	"time"

	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"golang.org/x/sys/unix"
)

func GenerateTrafficReport() *structs.TrafficReport {
	meta := structs.TrafficReportMetaData{
		SrcIP:   GenerateIP(),
		SrcPort: uint32(GeneratePort()),
		DstIP:   GenerateIP(),
		DstPort: uint32(GeneratePort()),
	}
	dir := consts.TRAFFIC_DIR_V4_EGRESS
	return &structs.TrafficReport{
		TrafficReportMeta: meta,
		Dir:               dir,
		Protocol:          unix.IPPROTO_TCP,
		Family:            unix.AF_INET,
		DataBytes:         uint32(rand.Int31()),
		Identity:          2,
		Timestamp:         time.Now(),
	}
}

func GenerateTrafficRecord() *structs.TrafficRecord {
	ip := GenerateIP()
	dir := consts.TRAFFIC_DIR_V4_EGRESS
	port := GeneratePort()
	tag := fmt.Sprintf("port:%v", port)
	return &structs.TrafficRecord{
		TrafficRecordMeta: structs.TrafficRecordMetaData{
			IP:  ip,
			Dir: dir,
			Tag: fmt.Sprintf("port:%v", tag),
		},
		DataBytes: uint32(rand.Int31()),
		ID:        fmt.Sprintf("%v/%v/%v", ip, tag, dir),
		Timestamp: time.Now(),
	}
}

func GeneratePort() int32 {
	return rand.Int31n(65536)
}

func GenerateIP() string {
	a := rand.Int31n(255) + 1
	b := rand.Int31n(255) + 1
	c := rand.Int31n(255) + 1
	d := rand.Int31n(255) + 1
	ip := fmt.Sprintf("%v.%v.%v.%v", a, b, c, d)
	return ip
}
