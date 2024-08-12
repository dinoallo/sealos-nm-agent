package node_watcher

import (
	"context"
	"os"
	"path/filepath"

	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/tc_bpf"
	"github.com/fsnotify/fsnotify"
	"github.com/puzpuzpuz/xsync"
	"github.com/vishvananda/netlink"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

const (
	defaultBindMountPath = "/run/netns"
	defaultPodMainIf     = "eth0"
	defaultFilterPrio    = 1

	ingressFilterNameForHostDev = "sealos_nm_host_ingress_hook"
	egressFilterNameForHostDev  = "sealos_nm_host_egress_hook"
	ingressFilterNameForPodDev  = "sealos_nm_pod_ingress_hook"
	egressFilterNameForPodDev   = "sealos_nm_pod_egress_hook"
)

type IfEntry struct {
	Name         string
	Qdisc        netlink.Qdisc
	EgressFilter netlink.Filter
}

func NewIfEntry(ifName string) *IfEntry {
	return &IfEntry{
		Name:         ifName,
		Qdisc:        nil,
		EgressFilter: nil,
	}
}

type NetnsEntry struct {
	// the name of this netns
	Name string
	// the hooker of this netns
	Hooker *tc_bpf.TcBpfHooker
	// the devices in this netns
	IfEntries *xsync.MapOf[string, *IfEntry]
}

func NewNetnsEntry(netnsName string) (*NetnsEntry, error) {
	newHooker, err := tc_bpf.NewTcBpfHooker(netnsName)
	if err != nil {
		return nil, err
	}
	entries := xsync.NewMapOf[*IfEntry]()
	netnsEntry := &NetnsEntry{
		Name:      netnsName,
		IfEntries: entries,
		Hooker:    newHooker,
	}
	return netnsEntry, nil
}

type NetnsWatcherParams struct {
	ParentLogger log.Logger
	modules.BPFTrafficFactory
}

type NetnsWatcher struct {
	log.Logger
	watcher      *fsnotify.Watcher
	netnsEntries *xsync.MapOf[string, *NetnsEntry] // netnsHash -> NetnsEntry
	waitQueue    chan string
	NetnsWatcherParams
}

func NewNetnsWatcher(params NetnsWatcherParams) (*NetnsWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("netns_watcher")
	if err != nil {
		return nil, err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &NetnsWatcher{
		Logger:             logger,
		watcher:            watcher,
		netnsEntries:       xsync.NewMapOf[*NetnsEntry](),
		waitQueue:          make(chan string, 10),
		NetnsWatcherParams: params,
	}, nil

}

func (w *NetnsWatcher) Start(ctx context.Context) error {
	w.startWatching(ctx)
	w.startProcessing(ctx)
	return nil
}

func (w *NetnsWatcher) startWatching(ctx context.Context) error {
	w.watcher.Add(defaultBindMountPath)
	go func() {
		for {
			select {
			case event, ok := <-w.watcher.Events:
				if !ok {
					w.Infof("the channel for events has been closed")
					return
				}
				//TODO: filter out non pod netns
				if event.Has(fsnotify.Create) {
					w.waitQueue <- event.Name
				}
			case err, ok := <-w.watcher.Errors:
				if !ok {
					w.Infof("the channel for errors has been closed")
					return
				}
				w.Errorf("err: %v", err)
			case <-ctx.Done():
			}
		}
	}()
	return nil
}

func (w *NetnsWatcher) startProcessing(ctx context.Context) error {
	go func() {
		for {
			select {
			case netnsPath := <-w.waitQueue:
				netnsName := filepath.Base(netnsPath)
				if err := w.updatePodNetns(netnsName); err == nil {
					continue
				} else {
					w.Errorf("failed to update pod netns %v: %v", netnsName, err)
				}
				netnsFullPath := filepath.Join(defaultBindMountPath, netnsPath)
				_, err := os.Stat(netnsFullPath)
				if err == nil {
					w.Info("retry updating pod netns %v", netnsName)
					w.waitQueue <- netnsPath
				} else if os.IsNotExist(err) {
					continue
				} else {
					w.Errorf("failed to check if pod netns %v exists", netnsName)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (w *NetnsWatcher) Close() {
	doResettingPodNetns := func(netnsHash string, netnsEntry *NetnsEntry) bool {
		if err := netnsEntry.removeClsactQdiscForAllIfs(); err != nil {
			w.Errorf("failed to remove the clsact qdisc for all interfaces inside pod netns %v: %v", netnsEntry.Name, err)
		}
		return true
	}
	w.netnsEntries.Range(doResettingPodNetns)
	w.watcher.Close()
}

func (w *NetnsWatcher) updatePodNetns(name string) error {
	newNetnsEntry, err := NewNetnsEntry(name)
	if err != nil {
		return err
	}
	netnsHash := getNetnsHash(name)
	netnsEntry, _ := w.netnsEntries.LoadOrStore(netnsHash, newNetnsEntry)
	return w.installFiltersOnPodMainIf(netnsEntry)
}

func (w *NetnsWatcher) resetPodNetns(name string) error {
	netnsHash := getNetnsHash(name)
	netnsEntry, loaded := w.netnsEntries.LoadAndDelete(netnsHash)
	if !loaded {
		return nil
	}
	return netnsEntry.removeClsactQdiscForAllIfs()
}

func (e *NetnsEntry) GetHash() string {
	return e.Name
}

func getNetnsHash(netnsName string) string {
	return netnsName
}

func getIfHash(ifName string) string {
	return ifName
}

func (e *NetnsEntry) removeClsactQdiscForAllIfs() error {
	bpfHooker := e.Hooker
	uninstallForEachIf := func(ifHash string, ifEntry *IfEntry) bool {
		if ifEntry.Qdisc == nil {
			return true
		}
		if err := bpfHooker.DelQdisc(ifEntry.Qdisc); err != nil {

		}
		return true
	}
	e.IfEntries.Range(uninstallForEachIf)
	return nil
}

func (w *NetnsWatcher) installFiltersOnPodMainIf(netnsEntry *NetnsEntry) error {
	// Currently, we expect that there are no other tc bpf programs except for ours
	// to avoid conflicts. That is, a clsact qdisc shouldn't exist beforehand and
	// it will then be created by us.
	if err := netnsEntry.installClsactQdiscOnPodMainIf(); err != nil {
		return nil
	}
	if err := netnsEntry.installEgressFilterOnIf(defaultPodMainIf, egressFilterNameForPodDev, w.GetEgressFilterFDForPodDev()); err != nil {
		return nil
	}
	return nil
}

func (e *NetnsEntry) installClsactQdiscOnPodMainIf() error {
	bpfHooker := e.Hooker
	qdisc, err := bpfHooker.AddClsactQdisc(defaultPodMainIf)
	if err != nil {
		return err
	}
	newIfEntry := NewIfEntry(defaultPodMainIf)
	podMainIfHash := getIfHash(defaultPodMainIf)
	ifEntry, _ := e.IfEntries.LoadOrStore(podMainIfHash, newIfEntry)
	ifEntry.Qdisc = qdisc
	return nil
}

func (e *NetnsEntry) installEgressFilterOnIf(ifName string, filterName string, fd int) error {
	bpfHooker := e.Hooker
	clsactQdiscFound, err := bpfHooker.CheckClsActQdisc(ifName)
	if err != nil {
		return err
	}
	if !clsactQdiscFound {
		// If the clsact qdisc doesn't exist on this interface, we don't do anything
		return nil
	}
	ifHash := getIfHash(ifName)
	newIfEntry := NewIfEntry(ifName)
	ifEntry, _ := e.IfEntries.LoadOrStore(ifHash, newIfEntry)
	filter, err := installEgressFilter(bpfHooker, filterName, ifName, fd)
	if err != nil {
		return err
	}
	ifEntry.EgressFilter = filter
	return nil
}

func installEgressFilter(bpfHooker *tc_bpf.TcBpfHooker, filterName, ifName string, fd int) (netlink.Filter, error) {
	opts := tc_bpf.AddFilterOption{
		FilterName: filterName,
		IfName:     ifName,
		ProgFD:     fd,
		Prio:       defaultFilterPrio,
	}
	return bpfHooker.AddEgressFilter(opts)
}
