package node_watcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/cenkalti/backoff/v4"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/tc_bpf"
	"github.com/fsnotify/fsnotify"
	"github.com/puzpuzpuz/xsync"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
)

const (
	defaultBindMountPath = "/run/netns"
	defaultFilterPrio    = 1

	ingressFilterNameForHostDev = "sealos_nm_host_ingress_hook"
	egressFilterNameForHostDev  = "sealos_nm_host_egress_hook"
	ingressFilterNameForPodDev  = "sealos_nm_pod_ingress_hook"
	egressFilterNameForPodDev   = "sealos_nm_pod_egress_hook"
)

var (
	ErrCheckingNetNsExists = errors.New("failed to check if the netns exists")
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
	conf.NetnsWatcherConfig
	modules.BPFTrafficFactory
}

type NetnsWatcher struct {
	log.Logger
	watcher              *fsnotify.Watcher
	netnsEntries         *xsync.MapOf[string, *NetnsEntry] // netnsHash -> NetnsEntry
	relevantNetnsPattern *regexp.Regexp
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
	re := regexp.MustCompile(params.NsPattern)
	return &NetnsWatcher{
		Logger:               logger,
		watcher:              watcher,
		netnsEntries:         xsync.NewMapOf[*NetnsEntry](),
		relevantNetnsPattern: re,
		NetnsWatcherParams:   params,
	}, nil

}

func (w *NetnsWatcher) Start(ctx context.Context) error {
	if err := w.initExistingNetns(); err != nil {
		return err
	}
	if err := w.watchInotifyEvent(ctx); err != nil {
		return err
	}
	return nil
}

func (w *NetnsWatcher) initExistingNetns() error {
	files, err := os.ReadDir(defaultBindMountPath)
	if err != nil {
		return err
	}
	//TODO: concurrently update
	var wg sync.WaitGroup
	fileChan := make(chan os.DirEntry, len(files))
	for i := 0; i < w.MaxWorkerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range fileChan {
				if file.IsDir() {
					continue
				}
				fileName := file.Name()
				if fileName == "." || fileName == ".." {
					continue
				}
				if err := w.updatePodNetnsByPath(fileName); err != nil {
					w.Errorf("failed to update pod netns %v: %v", fileName, err)
					continue
				}
			}
		}(i + 1)
	}
	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)
	wg.Wait()
	return nil
}

func (w *NetnsWatcher) watchInotifyEvent(ctx context.Context) error {
	w.watcher.Add(defaultBindMountPath)
	wg := errgroup.Group{}
	wg.SetLimit(w.MaxWorkerCount)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				wg.Go(func() error {
					w.handleInotifyEvent(ctx)
					return nil
				})
			}
		}
	}()
	return nil
}

func (w *NetnsWatcher) handleInotifyEvent(ctx context.Context) {
	select {
	case event, ok := <-w.watcher.Events:
		if !ok {
			w.Infof("the channel for events has been closed")
			return
		}
		if event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) {
			w.Debugf("receive event %v", event)
			if err := w.updatePodNetnsByPath(event.Name); err != nil {
				w.Errorf("failed to update pod netns %v due to %v", event.Name, err)
				return
			} else {
				w.Debugf("pod netns %v updated", event.Name)
				return
			}
		}
	case err, ok := <-w.watcher.Errors:
		if !ok {
			w.Infof("the channel for errors has been closed")
			return
		}
		w.Errorf("err: %v", err)
		return
	case <-ctx.Done():
		return
	}
}

func (w *NetnsWatcher) updatePodNetnsByPath(netnsPath string) error {
	netnsName := filepath.Base(netnsPath)
	if !w.isRelevantNetns(netnsName) {
		// this netns is not relevant to us. ignore it
		return nil
	}
	updateOp := func() error {
		w.Infof("try updating pod netns %v...", netnsName)
		return w.updatePodNetns(netnsName)
	}
	b := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), w.MaxUpdateRetries)
	return backoff.Retry(updateOp, b)
}

func (w *NetnsWatcher) Close() {
	doResettingPodNetns := func(netnsHash string, netnsEntry *NetnsEntry) bool {
		if err := netnsEntry.removeClsactQdiscForAllIfs(); err != nil {
			w.Errorf("failed to remove the clsact qdisc for all interfaces inside pod netns %v: %v", netnsEntry.Name, err)
		} else {
			w.Debugf("successfully remove the clsact qdisc for all interfaces inside pod netns %v", netnsEntry.Name)
		}
		return true
	}
	w.netnsEntries.Range(doResettingPodNetns)
	w.watcher.Close()
}

func (w *NetnsWatcher) updatePodNetns(netNsName string) error {
	netNsFullPath := filepath.Join(defaultBindMountPath, netNsName)
	netNsHash := getNetnsHash(netNsName)
	// verify that this net namespace still exists
	_, err := os.Stat(netNsFullPath)
	if os.IsNotExist(err) {
		// if this netns doesn't exist, we ignore it and remove its entry (if any)
		w.Debugf("pod netns %v doesn't exist. ignore it", netNsName)
		w.netnsEntries.Delete(netNsHash)
		return nil
	} else if err != nil {
		return errors.Join(err, ErrCheckingNetNsExists)
	}
	// this netns exists, so we try to install filters
	netnsHash := getNetnsHash(netNsName)
	newNetnsEntry, err := NewNetnsEntry(netnsHash)
	if err != nil {
		return err
	}
	netnsEntry, _ := w.netnsEntries.LoadOrStore(netnsHash, newNetnsEntry)
	return w.installFiltersOnPodMainIf(netnsEntry)
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
	var err error = nil
	uninstallForEachIf := func(ifHash string, ifEntry *IfEntry) bool {
		if ifEntry.Qdisc == nil {
			return true
		}
		err = bpfHooker.DelQdisc(ifEntry.Qdisc)
		return true
	}
	e.IfEntries.Range(uninstallForEachIf)
	return err
}

func (w *NetnsWatcher) installFiltersOnPodMainIf(netnsEntry *NetnsEntry) error {
	// Currently, we expect that there are no other tc bpf programs except for ours
	// to avoid conflicts. That is, a clsact qdisc shouldn't exist beforehand and
	// it will then be created by us.
	if err := netnsEntry.installClsactQdiscOnIf(w.PodIfName); err != nil {
		return err
	}
	if err := netnsEntry.installEgressFilterOnIf(w.PodIfName, egressFilterNameForPodDev, w.GetEgressFilterFDForPodDev()); err != nil {
		return err
	}
	return nil
}

func (w *NetnsWatcher) isRelevantNetns(netNsName string) bool {
	return w.relevantNetnsPattern.MatchString(netNsName)
}

func (e *NetnsEntry) installClsactQdiscOnIf(ifName string) error {
	bpfHooker := e.Hooker
	qdisc, err := bpfHooker.AddClsactQdisc(ifName)
	if err != nil {
		return err
	}
	newIfEntry := NewIfEntry(ifName)
	ifHash := getIfHash(ifName)
	ifEntry, _ := e.IfEntries.LoadOrStore(ifHash, newIfEntry)
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
