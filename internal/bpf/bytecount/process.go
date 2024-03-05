package bytecount

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/ebpf/perf"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
)

func (bf *BytecountFactory) readTraffic(ctx context.Context, eventReader *perf.Reader, d consts.TrafficDirection) error {
	log := bf.logger
	rec, err := eventReader.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			log.Infof("the perf event channel is closed")
			return nil
		} else {
			log.Errorf("unable to read from perf event reader: %v", err)
			return nil
		}
	}
	if rec.LostSamples != 0 {
		log.Infof("perf event ring buffer full, dropped %d samples", rec.LostSamples)
	}
	tr := Traffic{
		r: &rec,
		d: d,
	}
	bf.rawTrafficChannel <- &tr
	return nil
}

/*
func (bf *BytecountFactory) readTraffic(ctx context.Context, t uint32) error {
	log := bf.logger
	objs := bf.objs
	var eventArray *ebpf.Map
	switch t {
	case IPv4Ingress.TypeInt:
		eventArray = objs.IngressTrafficEvents
	case IPv4Egress.TypeInt:
		eventArray = objs.EgressTrafficEvents
	default:
		return fmt.Errorf("unknown direction")
	}
	er, err := perf.NewReader(eventArray, PERF_BUFFER_SIZE)
	if err != nil {
		return fmt.Errorf("failed to create a new reader: %v", err)
	}
	go func(ctx context.Context) {
		defer er.Close()
		<-ctx.Done()
	}(ctx)

	for {
		rec, err := er.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Infof("the perf event channel is closed")
				return nil
			} else {
				log.Errorf("unable to read from perf event reader: %v", err)
				return nil
			}
		}
		if rec.LostSamples != 0 {
			log.Infof("perf event ring buffer full, dropped %d samples", rec.LostSamples)
			continue
		}
		tr := Traffic{
			trafficRecord: &rec,
			trafficType:   t,
		}
		// go bf.processTraffic(ctx, tr)
		bf.rawTrafficChannel <- &tr
	}
}*/

func (bf *BytecountFactory) processTraffic(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case traffic := <-bf.rawTrafficChannel:
		var e bytecountTrafficEventT
		if traffic.r != nil {
			if err := binary.Read(bytes.NewBuffer(traffic.r.RawSample), bf.nativeEndian, &e); err != nil {
				return err
			}
			if err := bf.submit(ctx, &e, traffic.d); err != nil {
				return err
			}
		}
	}
	return nil
}

/*
func (bf *BytecountFactory) processTraffic(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case traffic := <-bf.rawTrafficChannel:
			log := bf.logger
			var event bytecountTrafficEventT
			if traffic.trafficRecord != nil {
				if err := binary.Read(bytes.NewBuffer(traffic.trafficRecord.RawSample), bf.nativeEndian, &event); err != nil {
					log.Infof("Failed to decode received data: %+v", err)
					return nil
				}
				t := traffic.trafficType
				if err := bf.submit(ctx, &event, t); err != nil {
					log.Infof("Failed to submit the traffic report: %+v", err)
					return nil
				}
			}
		}
	}
}*/

/*
func (bf *Factory) processTraffic(ctx context.Context, traffic Traffic) {
	log := bf.logger
	var event bytecountTrafficEventT
	if traffic.trafficRecord != nil {
		if err := binary.Read(bytes.NewBuffer(traffic.trafficRecord.RawSample), bf.nativeEndian, &event); err != nil {
			log.Infof("Failed to decode received data: %+v", err)
			return
		}
		t := traffic.trafficType
		if err := bf.submit(ctx, &event, t); err != nil {
			log.Infof("Failed to submit the traffic report: %+v", err)
			return
		}
	}
}*/

func (bf *BytecountFactory) submit(ctx context.Context, event *bytecountTrafficEventT, d consts.TrafficDirection) error {
	if event.Len <= 0 {
		return nil
	}
	__srcIP := make([]uint32, 4)
	__dstIP := make([]uint32, 4)
	var srcPort uint32
	var dstPort uint32
	__srcIP[0] = event.SrcIp4
	__dstIP[0] = event.DstIp4
	srcPort = event.SrcPort
	dstPort = uint32(event.DstPort)
	srcIP := util.ToIP(__srcIP[0], nil, 4)
	dstIP := util.ToIP(__dstIP[0], nil, 4)
	// skip the following addresses
	for _, ipAddr := range bf.ipAddrs {
		if srcIP.String() == ipAddr || dstIP.String() == ipAddr {
			return nil
		}
	}
	report := &structs.TrafficReport{
		TrafficReportMeta: structs.TrafficReportMetaData{
			SrcIP:   srcIP.String(),
			DstIP:   dstIP.String(),
			SrcPort: srcPort,
			DstPort: dstPort,
		},
		Dir:       d,
		Protocol:  event.Protocol,
		Family:    event.Family,
		DataBytes: event.Len,
		Identity:  identity.NumericIdentity(event.Identity),
		Timestamp: time.Now(),
	}
	// bf.logger.Infof("src_ip: %v => dst_ip: %v; %v bytes sent", srcIP.String(), dstIP.String(), event.Len)
	bf.param.TRS.AddTrafficReport(ctx, report)
	return nil
}
