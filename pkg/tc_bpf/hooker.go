package tc_bpf

import (
	"errors"

	"github.com/vishvananda/netlink"
	netns "github.com/vishvananda/netns"
)

type specialQdiscType int

const (
	qdiscRoot specialQdiscType = iota
	qdiscIngress
)

var (
	ErrClsactQdiscNotExists = errors.New("the clsact qdisc doesn't exist")
)

type TcBpfHooker struct {
	*netlink.Handle
}

func NewTcBpfHooker(nsName string) (*TcBpfHooker, error) {
	var handle *netlink.Handle
	var err error
	if nsName == "" {
		handle, err = getHandleFromCurrentNs()
	} else {
		handle, err = getHandleFromNs(nsName)
	}
	if err != nil {
		return nil, err
	}
	hooker := TcBpfHooker{
		Handle: handle,
	}
	return &hooker, nil
}

func (h *TcBpfHooker) AddClsactQdisc(ifName string) (netlink.Qdisc, error) {
	link, err := h.getLink(ifName)
	if err != nil {
		return nil, err
	}
	qdisc := Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := h.Handle.QdiscAdd(&qdisc); err != nil {
		return nil, err
	}
	return &qdisc, nil
}

func (h *TcBpfHooker) DelQdisc(qdisc netlink.Qdisc) error {
	return h.Handle.QdiscDel(qdisc)
}

func getHandleFromCurrentNs() (*netlink.Handle, error) {
	return netlink.NewHandle()
}

func getHandleFromNs(nsName string) (*netlink.Handle, error) {
	nsHandle, err := netns.GetFromName(nsName)
	if err != nil {
		return nil, err
	}
	handle, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

type AddFilterOption struct {
	// The name of this filter
	FilterName string
	// The name of the device to add filter to
	IfName string
	// The program fd of this filter
	ProgFD int
	// The priority of this program
	Prio uint16
}

func (h *TcBpfHooker) AddIngressFilter(opts AddFilterOption) (netlink.Filter, error) {
	return h.addFilter(qdiscIngress, opts)
}

func (h *TcBpfHooker) AddEgressFilter(opts AddFilterOption) (netlink.Filter, error) {
	return h.addFilter(qdiscRoot, opts)
}

func (h *TcBpfHooker) addFilter(sqt specialQdiscType, opts AddFilterOption) (netlink.Filter, error) {
	link, err := h.getLink(opts.IfName)
	if err != nil {
		return nil, err
	}
	ok, err := h.checkClsActQdisc(link)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrClsactQdiscNotExists
	}
	ifIndex := link.Attrs().Index
	attrs := getBpfFilterAttrs(ifIndex, opts.Prio, opts.Prio, sqt)
	bpfFilter := netlink.BpfFilter{
		FilterAttrs:  attrs,
		Fd:           opts.ProgFD,
		DirectAction: true,
	}
	if err := h.Handle.FilterAdd(&bpfFilter); err != nil {
		return nil, err
	}
	return &bpfFilter, nil
}

func (h *TcBpfHooker) DelFilter(filter netlink.Filter) error {
	if err := h.Handle.FilterDel(filter); err != nil {
		return err
	}
	return nil
}

func getBpfFilterAttrs(ifindex int, prio, proto uint16, sqt specialQdiscType) netlink.FilterAttrs {
	var parent uint32
	switch sqt {
	case qdiscIngress:
		parent = netlink.HANDLE_MIN_INGRESS
	default:
		parent = netlink.HANDLE_MIN_EGRESS
	}
	handle := netlink.MakeHandle(prio, proto)
	attrs := netlink.FilterAttrs{
		LinkIndex: ifindex,
		Handle:    handle,
		Parent:    parent,
		Priority:  prio,
		Protocol:  proto,
	}
	return attrs
}

func (h *TcBpfHooker) getLink(ifName string) (netlink.Link, error) {
	link, err := h.Handle.LinkByName(ifName)
	if err != nil {
		return nil, err
	}
	return link, err
}

func (h *TcBpfHooker) CheckClsActQdisc(ifName string) (bool, error) {
	link, err := h.getLink(ifName)
	if err != nil {
		return false, err
	}
	return h.checkClsActQdisc(link)
}

func (h *TcBpfHooker) checkClsActQdisc(link netlink.Link) (bool, error) {
	qdiscs, err := h.safeQdiscList(link)
	if err != nil {
		return false, err
	}
	if len(qdiscs) < 1 {
		return false, nil
	}
	var found bool = false
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			found = true
			break
		}
	}
	return found, nil
}

func (h *TcBpfHooker) safeQdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	qdiscs, err := h.Handle.QdiscList(link)
	if err != nil {
		return nil, err
	}
	result := []netlink.Qdisc{}
	for _, qdisc := range qdiscs {
		attrs := qdisc.Attrs()
		if attrs.Handle == netlink.HANDLE_NONE && attrs.Parent == netlink.HANDLE_ROOT {
			continue
		}
		result = append(result, qdisc)
	}
	return result, nil
}

type Clsact struct {
	netlink.QdiscAttrs
}

func (qdisc *Clsact) Attrs() *netlink.QdiscAttrs {
	return &qdisc.QdiscAttrs
}

func (qdisc *Clsact) Type() string {
	return "clsact"
}
