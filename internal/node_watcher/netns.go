package node_watcher

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"github.com/fsnotify/fsnotify"
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

type NetnsWatcherParams struct {
	ParentLogger log.Logger
	conf.NetnsWatcherConfig
	modules.BPFTrafficFactory
}

type NetnsWatcher struct {
	log.Logger
	watcher              *fsnotify.Watcher
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
		relevantNetnsPattern: re,
		NetnsWatcherParams:   params,
	}, nil

}

func (w *NetnsWatcher) Start(ctx context.Context) error {
	if err := w.watchInotifyEvent(ctx); err != nil {
		return err
	}
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
			netNsName := filepath.Base(event.Name)
			if !w.isRelevantNetns(netNsName) {
				return
			}
			if err := w.InitPod(netNsName); err != nil {
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

func (w *NetnsWatcher) Close() {
	w.watcher.Close()
}

func (w *NetnsWatcher) isRelevantNetns(netNsName string) bool {
	return w.relevantNetnsPattern.MatchString(netNsName)
}
