package tc_bpf

import (
	"errors"

	"github.com/vishvananda/netlink"
	netns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type specialQdiscType int

const (
	qdiscRoot specialQdiscType = iota
	qdiscIngress
)

var (
	ErrLinkNotExists        = errors.New("the link doesn't exist")
	ErrClsactQdiscNotExists = errors.New("the clsact qdisc doesn't exist")
	ErrClsactQdiscExists    = errors.New("the clsact qdisc already exists")
	ErrFilterNotExists      = errors.New("the filter doesn't exist")
	ErrFilterExists         = errors.New("the filter already exist")
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

func (h *TcBpfHooker) GetLink(ifName string) (netlink.Link, error) {
	return h.getLink(ifName)
}

func (h *TcBpfHooker) AddClsactQdisc(ifName string) (netlink.Qdisc, error) {
	link, err := h.getLink(ifName)
	if err != nil {
		return nil, err
	}
	// check if the clsact qdisc already exists. if it does, we return an Exist error
	qdisc := getClsactQdisc(link)
	exists, err := h.checkClsActQdisc(link)
	if err != nil {
		return nil, err
	}
	if exists {
		return qdisc, ErrClsactQdiscExists
	}
	// the clsact qdisc doesn't exist, let's create it
	if err := h.Handle.QdiscAdd(qdisc); err != nil {
		return nil, err
	}
	return qdisc, nil
}

func (h *TcBpfHooker) DelClsactQdisc(ifName string) error {
	link, err := h.getLink(ifName)
	if err != nil {
		return err
	}
	qdisc := getClsactQdisc(link)
	// check if the clsact qdisc exists. if it doesn't, we return an NonExist error
	exists, err := h.checkClsActQdisc(link)
	if err != nil {
		return err
	}
	if !exists {
		return ErrClsactQdiscNotExists
	}
	// the clsact qdisc exist, let's remove it
	return h.Handle.QdiscDel(qdisc)
}

func getClsactQdisc(link netlink.Link) netlink.Qdisc {
	return &Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
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

type FilterOption struct {
	// The name of the device to del filter from
	IfName string
	// The program fd of this filter
	ProgFD int
	// The priority of this program
	Prio uint16
}

func (h *TcBpfHooker) AddIngressFilter(opts FilterOption) (netlink.Filter, error) {
	return h.addFilter(qdiscIngress, opts)
}

func (h *TcBpfHooker) AddEgressFilter(opts FilterOption) (netlink.Filter, error) {
	return h.addFilter(qdiscRoot, opts)
}

func (h *TcBpfHooker) DelIngressFilter(opts FilterOption) error {
	return h.delFilter(qdiscIngress, opts)
}

func (h *TcBpfHooker) DelEgressFilter(opts FilterOption) error {
	return h.delFilter(qdiscRoot, opts)
}

func (h *TcBpfHooker) addFilter(sqt specialQdiscType, opts FilterOption) (netlink.Filter, error) {
	link, err := h.getLink(opts.IfName)
	if err != nil {
		return nil, err
	}
	// check if the clsact qdisc exists. if it doesn't, we return a NotExists error
	ok, err := h.checkClsActQdisc(link)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrClsactQdiscNotExists
	}
	bpfFilter := getBpfFilter(link, opts.ProgFD, opts.Prio, unix.ETH_P_ALL, sqt)
	// check if the filter exists. if it does, we return an Exist error
	ok, err = h.checkFilter(link, bpfFilter)
	if err != nil {
		return nil, err
	}
	if ok {
		return bpfFilter, ErrFilterExists
	}
	// the filter doesn't exist, let's create it
	if err := h.Handle.FilterAdd(bpfFilter); err != nil {
		return nil, err
	}
	return bpfFilter, nil
}

func (h *TcBpfHooker) delFilter(sqt specialQdiscType, opts FilterOption) error {
	link, err := h.getLink(opts.IfName)
	if err != nil {
		return err
	}
	ok, err := h.checkClsActQdisc(link)
	if err != nil {
		return err
	}
	if !ok {
		return ErrClsactQdiscNotExists
	}
	// check if the filter exists. if it doesn't, we return a NotExist error
	bpfFilter := getBpfFilter(link, opts.ProgFD, opts.Prio, unix.ETH_P_ALL, sqt)
	ok, err = h.checkFilter(link, bpfFilter)
	if err != nil {
		return err
	}
	if !ok {
		return ErrFilterNotExists
	}
	if err := h.Handle.FilterDel(bpfFilter); err != nil {
		return err
	}
	return nil
}

func getBpfFilter(link netlink.Link, progFD int, prio, proto uint16, sqt specialQdiscType) netlink.Filter {
	ifIndex := link.Attrs().Index
	attrs := getBpfFilterAttrs(ifIndex, prio, proto, sqt)
	bpfFilter := netlink.BpfFilter{
		FilterAttrs:  attrs,
		Fd:           progFD,
		DirectAction: true,
	}
	return &bpfFilter
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
		_, ok := err.(netlink.LinkNotFoundError)
		if ok {
			return nil, ErrLinkNotExists
		}
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

func (h *TcBpfHooker) checkFilter(link netlink.Link, filter netlink.Filter) (bool, error) {
	filters, err := h.Handle.FilterList(link, filter.Attrs().Parent)
	if err != nil {
		return false, err
	}
	var found bool = false
	for _, _filter := range filters {
		if _filter.Type() != filter.Type() {
			continue
		}
		if _filter.Attrs().Handle != filter.Attrs().Handle {
			continue
		}
		found = true
		break
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
