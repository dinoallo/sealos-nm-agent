package cilium_ccm

import (
	"context"
	"errors"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/puzpuzpuz/xsync"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"

	ciliumbpffs "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/fs"
)

type actionKind int

const (
	actionSubscribe actionKind = iota
	actionUnsubscribe
)

var (
	ErrGettingCeps = errors.New("failed to get all cilium endpoints")
)

type CepMsg struct {
	eid    int64
	action actionKind
}

type CiliumCCMWatcherConfig struct {
	Enabled     bool
	WatchPeriod time.Duration
}

func NewCiliumCCMWatcherConfig() CiliumCCMWatcherConfig {
	return CiliumCCMWatcherConfig{
		Enabled:     false,
		WatchPeriod: time.Second * 10,
	}
}

type CiliumCCMWatcherParams struct {
	ParentLogger log.Logger
	CiliumCCMWatcherConfig
	modules.BPFTrafficFactory
	ciliumbpffs.CiliumBPFFS_
}

// watcher for cilium custom call map
type CiliumCCMWatcher struct {
	log.Logger
	cepToSync  chan CepMsg
	cepWatched *xsync.MapOf[int64, struct{}]
	CiliumCCMWatcherParams
}

func NewCiliumCCMWatcher(params CiliumCCMWatcherParams) (*CiliumCCMWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("cilium_ccm_watcher")
	if err != nil {
		return nil, errors.Join(err, modules.ErrCreatingLogger)
	}
	return &CiliumCCMWatcher{
		Logger:                 logger,
		CiliumCCMWatcherParams: params,
		cepToSync:              make(chan CepMsg),
		cepWatched:             xsync.NewIntegerMapOf[int64, struct{}](),
	}, nil
}

func (w *CiliumCCMWatcher) Start(ctx context.Context) error {
	if !w.Enabled {
		return nil
	}
	go func() {
		for {
			if err := w.watch(ctx); err != nil {
				w.Error(err)
				return
			}
			time.Sleep(w.WatchPeriod)
		}
	}()
	go func() {
		for {
			if err := w.sync(ctx); err != nil {
				w.Error(err)
				return
			}
		}
	}()
	w.Debugf("ready")
	return nil
}

func (w *CiliumCCMWatcher) sync(ctx context.Context) error {
	var msg CepMsg
	select {
	case <-ctx.Done():
	case msg = <-w.cepToSync:
	}
	var err error
	eid := msg.eid
	if msg.action == actionSubscribe {
		err = w.SubscribeToCep(eid)
	} else if msg.action == actionUnsubscribe {
		err = w.UnsubscribeFromCep(eid)
	}
	if errors.Is(err, modules.ErrCepNotFound) {
		return nil
	} else if err != nil {
		select {
		case <-ctx.Done():
		case w.cepToSync <- msg:
		}
	}
	return err
}

func (w *CiliumCCMWatcher) watch(ctx context.Context) error {
	eids, err := w.Ceps()
	if err != nil {
		return errors.Join(err, ErrGettingCeps)
	}
	newCeps := make(map[int64]struct{})
	for _, eid := range eids {
		newCeps[eid] = struct{}{}
	}
	deleteStaleCep := func(eid int64, v struct{}) bool {
		if _, ok := newCeps[eid]; !ok {
			UnsubMsg := CepMsg{
				eid:    eid,
				action: actionUnsubscribe,
			}
			select {
			case <-ctx.Done():
			case w.cepToSync <- UnsubMsg:
				w.cepWatched.Delete(eid)
			}
		}
		return true
	}
	w.cepWatched.Range(deleteStaleCep)
	for eid := range newCeps {
		if _, loaded := w.cepWatched.Load(eid); loaded {
			continue
		}
		msg := CepMsg{
			eid:    eid,
			action: actionSubscribe,
		}
		select {
		case <-ctx.Done():
		case w.cepToSync <- msg:
			w.cepWatched.Store(eid, struct{}{})
		}
	}
	return nil
}
