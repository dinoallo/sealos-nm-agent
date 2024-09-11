package traffic

import (
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/tc_bpf"
	"github.com/puzpuzpuz/xsync"
)

type FilterEntry struct {
	Name string
	FD   int
	Prio uint16
}

func NewFilterEntry(filterName string, fd int, prio uint16) *FilterEntry {
	return &FilterEntry{
		Name: filterName,
		FD:   fd,
		Prio: prio,
	}
}

type IfEntry struct {
	Name           string
	IngressFilters *xsync.MapOf[string, *FilterEntry]
	EgressFilters  *xsync.MapOf[string, *FilterEntry]
}

func NewIfEntry(ifName string) *IfEntry {
	return &IfEntry{
		Name:           ifName,
		IngressFilters: xsync.NewMapOf[*FilterEntry](),
		EgressFilters:  xsync.NewMapOf[*FilterEntry](),
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

func (e *NetNsEntry) installEgressFilterOnIf(ifName string, filterName string, fd int, prio uint16) error {
	err := e.ensureEgressFilterExists(ifName, fd, prio)
	if err != nil {
		return err
	}
	ifHash := getIfHash(ifName)
	newIfEntry := NewIfEntry(ifName)
	ifEntry, _ := e.IfEntries.LoadOrStore(ifHash, newIfEntry)
	filterEntry := NewFilterEntry(filterName, fd, prio)
	ifEntry.EgressFilters.Store(filterName, filterEntry)
	return nil
}

func (e *NetNsEntry) removeEgressFilterOnIf(ifName string, filterName string) error {
	ifHash := getIfHash(ifName)
	ifEntry, loaded := e.IfEntries.Load(ifHash)
	if !loaded {
		return nil
	}
	filterEntry, loaded := ifEntry.EgressFilters.LoadAndDelete(filterName)
	if !loaded {
		return nil
	}
	return e.ensureEgressFilterNotExists(ifName, filterEntry.Prio)
}

func (e *NetNsEntry) cleanUpFiltersOnAllIfs() error {
	var err error = nil
	cleanUpEgressFiltersForEachIf := func(ifHash string, ifEntry *IfEntry) bool {
		filters := ifEntry.EgressFilters
		cleanUpFilter := func(filterName string, filterEntry *FilterEntry) bool {
			filterEntry, loaded := filters.LoadAndDelete(filterName)
			if !loaded || filterEntry.FD == -1 {
				return true
			}
			err = e.ensureEgressFilterNotExists(ifEntry.Name, filterEntry.Prio)
			return true
		}
		// clean up egress filters
		ifEntry.EgressFilters.Range(cleanUpFilter)
		return true
	}
	e.IfEntries.Range(cleanUpEgressFiltersForEachIf)
	return err
}

func (e *NetNsEntry) ensureEgressFilterExists(ifName string, fd int, prio uint16) error {
	bpfHooker := e.Hooker
	opts := tc_bpf.FilterOption{
		IfName: ifName,
		ProgFD: fd,
		Prio:   prio,
	}
	err := e.ensureClsactQdiscOnIfExists(ifName)
	if err != nil && err != tc_bpf.ErrClsactQdiscExists {
		return err
	}
	_, err = bpfHooker.AddEgressFilter(opts)
	if err != nil && err != tc_bpf.ErrFilterExists {
		return err
	}
	return nil
}

func (e *NetNsEntry) ensureEgressFilterNotExists(ifName string, prio uint16) error {
	bpfHooker := e.Hooker
	opts := tc_bpf.FilterOption{
		IfName: ifName,
		Prio:   prio,
	}
	err := bpfHooker.DelEgressFilter(opts)
	if err != nil && err != tc_bpf.ErrClsactQdiscNotExists && err != tc_bpf.ErrFilterNotExists {
		return err
	}
	return nil
}

func (e *NetNsEntry) ensureClsactQdiscOnIfExists(ifName string) error {
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

func (e *NetNsEntry) GetHash() string {
	return e.Name
}
