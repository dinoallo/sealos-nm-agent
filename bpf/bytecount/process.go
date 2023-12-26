package bytecount

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/dinoallo/sealos-networkmanager-agent/util"
	"golang.org/x/sys/unix"
)

func (bf *Factory) Launch(ctx context.Context) error {
	log := bf.logger
	bf.objs = bytecountObjects{}

	log.Infof("loading bpf program objects...")
	if err := loadBytecountObjects(&bf.objs, nil); err != nil {
		log.Infof("unable to load the counter program to the kernel and assign it.")
		return util.ErrBPFProgramNotLoaded
	}
	go func(ctx context.Context) {
		defer bf.objs.Close()
		<-ctx.Done()
	}(ctx)
	IPv4Ingress.ClsProgram = bf.objs.IngressBytecountCustomHook
	IPv4Egress.ClsProgram = bf.objs.EgressBytecountCustomHook

	log.Infof("launching traffic event reader...")
	go bf.readTraffic(ctx, IPv4Egress.TypeInt)
	for i := 0; i < TRAFFIC_CONSUMER_COUNT; i++ {
		log.Infof("launching traffic event consumer...")
		go bf.processTraffic(ctx)
	}
	log.Infof("traffic counting factory launched")
	return nil
}

func (bf *Factory) readTraffic(ctx context.Context, t uint32) {
	log := bf.logger
	objs := bf.objs
	var eventArray *ebpf.Map
	switch t {
	case IPv4Ingress.TypeInt:
		eventArray = objs.IngressTrafficEvents
	case IPv4Egress.TypeInt:
		eventArray = objs.EgressTrafficEvents
	default:
		return
	}
	er, err := perf.NewReader(eventArray, PERF_BUFFER_SIZE)
	if err != nil {
		log.Errorf("failed to create a new reader")
		return
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
				return
			} else {
				log.Infof("reading from perf event reader: %v", err)
				continue
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
		bf.workQueue <- tr
	}
}

func (bf *Factory) processTraffic(ctx context.Context) {
	log := bf.logger

	for {
		select {
		case <-ctx.Done():
			break
		case traffic := <-bf.workQueue:
			var event bytecountTrafficEventT
			if traffic.trafficRecord != nil {
				if err := binary.Read(bytes.NewBuffer(traffic.trafficRecord.RawSample), bf.nativeEndian, &event); err != nil {
					log.Infof("Failed to decode received data: %+v", err)
					continue
				}
				t := traffic.trafficType
				if err := bf.submit(ctx, &event, t); err != nil {
					log.Infof("Failed to submit the traffic report: %+v", err)
					continue
				}
			}
		}
	}
}

func (bf *Factory) submit(ctx context.Context, event *bytecountTrafficEventT, t uint32) error {
	var dir store.TrafficDirection
	__srcIP := make([]uint32, 4)
	__dstIP := make([]uint32, 4)
	var srcPort uint32
	var dstPort uint32
	switch t {
	case IPv4Ingress.TypeInt:
		dir = store.V4Ingress
		__srcIP[0] = event.DstIp4
		__dstIP[0] = event.SrcIp4
		srcPort = uint32(event.DstPort)
		dstPort = event.SrcPort
	case IPv4Egress.TypeInt:
		dir = store.V4Egress
		__srcIP[0] = event.SrcIp4
		__dstIP[0] = event.DstIp4
		srcPort = event.SrcPort
		dstPort = uint32(event.DstPort)
	default:
		return nil
	}

	if event.Family == unix.AF_INET || event.Family == unix.AF_INET6 {
		report := &store.TrafficReport{
			Dir:       dir,
			Protocol:  event.Protocol,
			SrcIP:     util.ToIP(__srcIP[0], nil, 4),
			DstIP:     util.ToIP(__dstIP[0], nil, 4),
			SrcPort:   srcPort,
			DstPort:   dstPort,
			DataBytes: event.Len,
			Identity:  identity.NumericIdentity(event.Identity),
		}
		// log.Debugf("protocol: %v; %v bytes sent", event.Protocol, event.Len)
		bf.store.AddTrafficReport(ctx, report)
		if bf.bytecountExportChannel != nil {
			bf.bytecountExportChannel <- report
		}
	}
	return nil
}
