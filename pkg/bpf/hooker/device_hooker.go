package hooker

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/bpf/common"
	errutil "github.com/dinoallo/sealos-networkmanager-agent/pkg/errors/util"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	clsActQdiscHandle uint32 = core.BuildHandle(tc.HandleRoot, 0)
)

type DeviceHooker struct {
	iface  string
	logger log.Logger
	// clsActQdisc *tc.Object
	filters *sync.Map
	tcnl    *tc.Tc
	devID   *net.Interface
	close   *sync.Once
}

func NewDeviceHooker(iface string, logger log.Logger) (*DeviceHooker, error) {
	return &DeviceHooker{
		iface:  iface,
		logger: logger,
		//	clsActQdisc: clsActQdisc,
		filters: &sync.Map{},
		tcnl:    nil,
		devID:   nil,
		close:   &sync.Once{},
	}, nil
}

// TODO: check if tcnl and devID is nil
// `Init` initialize `tcnl` and `devID`. Please call this function before calling any of other functions
func (h *DeviceHooker) Init() error {
	devID, err := net.InterfaceByName(h.iface)
	if err != nil {
		return errutil.Err(ErrGettingInterfaceName, err)
	}
	h.devID = devID
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return errutil.Err(ErrEstablishingSocket, err)
	}
	// set option `NETLINK_EXT_ACK`
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		closeTCNL(tcnl, h.logger)
		return errutil.Err(ErrSettingExtAck, err)
	}
	h.tcnl = tcnl
	_, err = setUpClsActQdisc(tcnl, devID)
	if err != nil {
		// closeQdisc(tcnl, clsActQdisc, logger)
		closeTCNL(tcnl, h.logger)
		return errutil.Err(ErrSettingUpQdisc, err)
	}
	return nil
}

func newClsActQdisc(devID *net.Interface, handle uint32) (*tc.Object, error) {
	qdisc := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  handle,
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	return qdisc, nil
}

func setUpClsActQdisc(tcnl *tc.Tc, devID *net.Interface) (*tc.Object, error) {
	existingQdiscs, err := tcnl.Qdisc().Get()
	if err != nil {
		return nil, err
	}
	// check if the clsact qdisc exists
	for _, qdisc := range existingQdiscs {
		if qdisc.Msg.Handle == clsActQdiscHandle {
			if qdisc.Attribute.Kind == "clsact" {
				return nil, nil
			} else {
				// !?
				return nil, fmt.Errorf("clsact handle used, but no clsact qdisc?")
			}
		}
	}
	// the clsact qdisc doesn't exist, create one by us
	clsActQdisc, err := newClsActQdisc(devID, clsActQdiscHandle)
	if err != nil {
		return nil, err
	}
	if err := tcnl.Qdisc().Add(clsActQdisc); err != nil {
		return nil, err
	}
	return clsActQdisc, nil
}

func (hooker *DeviceHooker) AddFilter(filterName string, hook *ebpf.Program, dir common.TCDirection) error {
	if hook == nil {
		return ErrProgramHookInvalid
	}
	parent, err := getParent(dir)
	if err != nil {
		return errutil.Err(ErrGettingParentHandle, err)
	}
	var filters *sync.Map = hooker.filters
	fd := uint32(hook.FD())
	flags := uint32(0x1)
	//TODO: check if the host is little-endian to use htons
	var prio uint32 = 42
	var protocol uint16 = htons(unix.ETH_P_ALL)
	var info uint32 = core.BuildHandle(prio, uint32(protocol))
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(hooker.devID.Index),
			Parent:  parent,
			Info:    info, // (prio << 16) & protocol
			// Info: 0xa0300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}
	if err := hooker.tcnl.Filter().Add(&filter); err != nil {
		return errutil.Err(ErrAddingFilter, err)
	}
	filters.Store(filterName, &filter)
	return nil
}

// func (hooker *DeviceHooker) GetFilter(filterName string) (*tc.Object, error) {
// 	_filter, loaded := hooker.filters.Load(filterName)
// 	if !loaded {
// 		return nil, fmt.Errorf("filter doesn't exist") //TODO: add me to the errors
// 	}
// 	filter, ok := (_filter).(*tc.Object)
// 	if !ok {
// 		// !?
// 		return nil, fmt.Errorf("") //TODO: fix me
// 	}
// 	return filter, nil
// }

func getParent(dir common.TCDirection) (uint32, error) {
	switch dir {
	case common.TC_DIR_INGRESS:
		return core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress), nil
	case common.TC_DIR_EGRESS:
		return core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress), nil
	}
	return 0, common.ErrUnknownTCDirection
}

func (hooker *DeviceHooker) RemoveFilter(filterName string) error {
	_filter, loaded := hooker.filters.LoadAndDelete(filterName)
	if !loaded {
		return nil
	}
	filter, ok := (_filter).(*tc.Object)
	if !ok {
		return errutil.Err(ErrFilterInvalid, nil)
	}
	if err := hooker.tcnl.Filter().Delete(filter); err != nil {
		return errutil.Err(ErrDeletingFilter, err)
	}
	return nil
}

func (hooker *DeviceHooker) Close() error {
	hooker.close.Do(func() {
		// closeQdisc(hooker.tcnl, hooker.clsActQdisc, hooker.logger)
		removeFilter := func(key, item any) bool {
			filter, ok := item.(*tc.Object)
			if !ok {
				// !?
				return true
			}
			if err := hooker.tcnl.Filter().Delete(filter); err != nil {
				hooker.logger.Errorf("%v", err)
				return true
			}
			return true
		}
		hooker.filters.Range(removeFilter)
		if err := closeTCNL(hooker.tcnl, hooker.logger); err != nil {
			hooker.logger.Error(errutil.Err(ErrClosingSocket, err))
		}
	})
	return nil

}

func closeTCNL(tcnl *tc.Tc, logger log.Logger) error {
	if err := tcnl.Close(); err != nil {
		return err
	}
	return nil
}

func closeQdisc(tcnl *tc.Tc, qdisc *tc.Object, logger log.Logger) error {
	if err := tcnl.Qdisc().Delete(qdisc); err != nil {
		return err
	}
	return nil
}

func htons(v uint16) uint16 {
	return (v>>8)&0xff00 | (v<<8)&0xff00
}
