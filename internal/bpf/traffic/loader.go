package traffic

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/cenkalti/backoff/v4"
	"github.com/cilium/ebpf"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"github.com/puzpuzpuz/xsync"
)

const (
	defaultBindMountPath = "/run/netns"
	defaultFilterPrio    = 1
	defaultPodMainIf     = "eth0"

	ingressFilterNameForHostDev = "sealos_nm_host_ingress_hook"
	egressFilterNameForHostDev  = "sealos_nm_host_egress_hook"
	ingressFilterNameForPodDev  = "sealos_nm_pod_ingress_hook"
	egressFilterNameForPodDev   = "sealos_nm_pod_egress_hook"

	fromContainerProgFile          = "sealos_nm_from_container_prog"
	toNetDevProgFile               = "sealos_nm_to_netdev_prog"
	fromContainerTrafficEventsFile = "sealos_nm_from_container_traffic_events_map"
	fromContainerTrafficNotisFile  = "sealos_nm_from_container_traffic_notis_map"
	toNetDevTrafficEventsFile      = "sealos_nm_to_netdev_traffic_events_map"
	toNetDevTrafficNotisFile       = "sealos_nm_to_netdev_traffic_notis_map"
)

var (
	ErrCheckingNetNsExists = errors.New("failed to check if the netns exists")
)

type TrafficHookerParams struct {
	ParentLogger     log.Logger
	TrafficObjs      *trafficObjects
	MaxWorkerCount   int
	MaxUpdateRetries uint64
}

type TrafficHooker struct {
	log.Logger
	hostNetNsEntry *NetNsEntry
	netNsEntries   *xsync.MapOf[string, *NetNsEntry]
	TrafficHookerParams
}

func NewTrafficHooker(params TrafficHookerParams) (*TrafficHooker, error) {
	logger, err := params.ParentLogger.WithCompName("traffic_hooker")
	if err != nil {
		return nil, err
	}
	hostNetnsEntry, err := NewNetNsEntry("")
	if err != nil {
		return nil, err
	}
	return &TrafficHooker{
		Logger:              logger,
		hostNetNsEntry:      hostNetnsEntry,
		netNsEntries:        xsync.NewMapOf[*NetNsEntry](),
		TrafficHookerParams: params,
	}, nil
}

func (h *TrafficHooker) Init() error {
	if err := h.initExistingPods(); err != nil {
		return err
	}
	return nil
}

func (h *TrafficHooker) InitPod(netNs string) error {
	return h.tryUpdatingTCHooksForPod(netNs)
}

func (h *TrafficHooker) InitHostIface(ifName string) error {
	return h.tryUpdatingTCHooksForHost(ifName)
}

func (h *TrafficHooker) Close() error {
	var err error
	// clean up for pods
	cleanUp := func(netNsHash string, netNsEntry *NetNsEntry) bool {
		if err = netNsEntry.cleanUpFiltersOnAllIfs(); err != nil {
			h.Errorf("failed to remove the filters for all interfaces inside pod netns %v: %v", netNsEntry.Name, err)
		} else {
			h.Debugf("successfully remove the filters for all interfaces inside pod netns %v", netNsEntry.Name)
		}
		return true
	}
	h.netNsEntries.Range(cleanUp)
	// clean up for host
	if err = h.hostNetNsEntry.cleanUpFiltersOnAllIfs(); err != nil {
		h.Errorf("failed to remove the filters for all interfaces in the host netns: %v", err)
	} else {
		h.Debugf("successfully remove the filters for all interfaces in the host netns")
	}
	return err
}

func (h *TrafficHooker) initExistingPods() error {
	files, err := os.ReadDir(defaultBindMountPath)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	fileChan := make(chan os.DirEntry, len(files))
	for i := 0; i < h.MaxWorkerCount; i++ {
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
				netNs := filepath.Base(fileName)
				if err := h.tryUpdatingTCHooksForPod(netNs); err != nil {
					h.Errorf("failed to update pod netns %v: %v", fileName, err)
					continue
				}
				h.Infof("pod netns %v updated", netNs)
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

func (h *TrafficHooker) tryUpdatingTCHooksForPod(netNs string) error {
	updateOp := func() error {
		h.Debugf("try updating pod of netns %v...", netNs)
		return h.updateTCHooksForPod(netNs)
	}
	b := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), h.MaxUpdateRetries)
	return backoff.Retry(updateOp, b)
}

func (h *TrafficHooker) tryUpdatingTCHooksForHost(ifName string) error {
	updateOp := func() error {
		h.Infof("try updating interface %v on host", ifName)
		return h.updateTCHooksForHost(ifName)
	}
	b := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), h.MaxUpdateRetries)
	return backoff.Retry(updateOp, b)
}

func (h *TrafficHooker) updateTCHooksForHost(ifName string) error {
	e := h.hostNetNsEntry
	// verify that the interface still exists
	exists, err := e.checkLinkExists(ifName)
	if err != nil {
		return err
	}
	if !exists {
		h.Debugf("interface %v doesn't exist. ignore it", ifName)
		ifHash := getIfHash(ifName)
		e.IfEntries.Delete(ifHash)
		return nil
	}
	return h.installFilterOnHostIf(ifName)
}

func (h *TrafficHooker) updateTCHooksForPod(netNs string) error {
	netNsFullPath := filepath.Join(defaultBindMountPath, netNs)
	netNsHash := getNetnsHash(netNs)
	// verify that this net namespace still exists
	_, err := os.Stat(netNsFullPath)
	if os.IsNotExist(err) {
		// if this netns doesn't exist, we ignore it and remove its entry (if any)
		h.Debugf("pod netns %v doesn't exist. ignore it", netNs)
		h.netNsEntries.Delete(netNsHash)
		return nil
	} else if err != nil {
		return errors.Join(err, ErrCheckingNetNsExists)
	}
	// this netns exists, so we try to install filters
	netnsHash := getNetnsHash(netNs)
	newNetnsEntry, err := NewNetNsEntry(netnsHash)
	if err != nil {
		return err
	}
	netnsEntry, _ := h.netNsEntries.LoadOrStore(netnsHash, newNetnsEntry)
	return h.installFiltersOnPodMainIf(netnsEntry)
}

func getIfHash(ifName string) string {
	return ifName
}

func (h *TrafficHooker) installFilterOnIf(netnsEntry *NetNsEntry, ifName string, prog *ebpf.Program) error {
	if err := netnsEntry.installClsactQdiscOnIf(ifName); err != nil {
		return err
	}
	// remove stale filters (if any)
	if err := netnsEntry.removeEgressFilterOnIf(ifName); err != nil {
		return err
	}
	// install filters
	if prog != nil && prog.FD() > -1 {
		if err := netnsEntry.installEgressFilterOnIf(ifName, prog.FD()); err != nil {
			return err
		}
	}
	return nil
}

func (h *TrafficHooker) installFilterOnHostIf(ifName string) error {
	return h.installFilterOnIf(h.hostNetNsEntry, ifName, h.TrafficObjs.SealosToNetdev)
}

func (h *TrafficHooker) installFiltersOnPodMainIf(netnsEntry *NetNsEntry) error {
	ifName := defaultPodMainIf
	return h.installFilterOnIf(netnsEntry, ifName, h.TrafficObjs.SealosFromContainer)
}
