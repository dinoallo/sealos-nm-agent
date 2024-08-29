package traffic

import (
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/tc_bpf"
	"github.com/puzpuzpuz/xsync"
	"github.com/vishvananda/netlink"
)

type IfEntry struct {
	Name           string
	EgressFilterFD int
}

func NewIfEntry(ifName string) *IfEntry {
	return &IfEntry{
		Name:           ifName,
		EgressFilterFD: -1,
	}
}

type NetNsEntry struct {
	// the name of this netns
	Name string
	// the hooker of this netns
	Hooker *tc_bpf.TcBpfHooker
	// the devices in this netns
	IfEntries *xsync.MapOf[string, *IfEntry]
}

func NewNetNsEntry(netnsName string) (*NetNsEntry, error) {
	newHooker, err := tc_bpf.NewTcBpfHooker(netnsName)
	if err != nil {
		return nil, err
	}
	entries := xsync.NewMapOf[*IfEntry]()
	netnsEntry := &NetNsEntry{
		Name:      netnsName,
		IfEntries: entries,
		Hooker:    newHooker,
	}
	return netnsEntry, nil
}

func (e *NetNsEntry) checkLinkExists(ifName string) (bool, error) {
	bpfHooker := e.Hooker
	_, err := bpfHooker.GetLink(ifName)
	if err == nil {
		return true, nil
	} else if err == tc_bpf.ErrLinkNotExists {
		return false, nil
	} else {
		return false, err
	}
}

func (e *NetNsEntry) installClsactQdiscOnIf(ifName string) error {
	bpfHooker := e.Hooker
	_, err := bpfHooker.AddClsactQdisc(ifName)
	if err != nil && err != tc_bpf.ErrClsactQdiscExists {
		return err
	}
	newIfEntry := NewIfEntry(ifName)
	ifHash := getIfHash(ifName)
	e.IfEntries.LoadOrStore(ifHash, newIfEntry)
	return nil
}

func (e *NetNsEntry) installEgressFilterOnIf(ifName string, fd int) error {
	bpfHooker := e.Hooker
	_, err := installEgressFilter(bpfHooker, ifName, fd)
	if err != nil && err != tc_bpf.ErrFilterExists {
		return err
	}
	ifHash := getIfHash(ifName)
	newIfEntry := NewIfEntry(ifName)
	ifEntry, _ := e.IfEntries.LoadOrStore(ifHash, newIfEntry)
	ifEntry.EgressFilterFD = fd
	return nil
}

func (e *NetNsEntry) removeEgressFilterOnIf(ifName string) error {
	bpfHooker := e.Hooker
	err := removeEgressFilter(bpfHooker, ifName)
	if err != nil && err != tc_bpf.ErrFilterNotExists {
		return err
	}
	ifHash := getIfHash(ifName)
	newIfEntry := NewIfEntry(ifName)
	ifEntry, _ := e.IfEntries.LoadOrStore(ifHash, newIfEntry)
	ifEntry.EgressFilterFD = -1
	return nil
}

func (e *NetNsEntry) cleanUpFiltersOnAllIfs() error {
	bpfHooker := e.Hooker
	var err error = nil
	cleanUpFilterForEachIf := func(ifHash string, ifEntry *IfEntry) bool {
		if ifEntry.EgressFilterFD == -1 {
			return true
		}
		opts := tc_bpf.FilterOption{
			IfName: ifEntry.Name,
			ProgFD: ifEntry.EgressFilterFD,
			Prio:   defaultFilterPrio,
		}
		err = bpfHooker.DelEgressFilter(opts)
		return true
	}
	e.IfEntries.Range(cleanUpFilterForEachIf)
	return err
}

func installEgressFilter(bpfHooker *tc_bpf.TcBpfHooker, ifName string, fd int) (netlink.Filter, error) {
	opts := tc_bpf.FilterOption{
		IfName: ifName,
		ProgFD: fd,
		Prio:   defaultFilterPrio,
	}
	return bpfHooker.AddEgressFilter(opts)
}

func removeEgressFilter(bpfHooker *tc_bpf.TcBpfHooker, ifName string) error {
	opts := tc_bpf.FilterOption{
		IfName: ifName,
		Prio:   defaultFilterPrio,
	}
	return bpfHooker.DelEgressFilter(opts)
}

func (e *NetNsEntry) GetHash() string {
	return e.Name
}
