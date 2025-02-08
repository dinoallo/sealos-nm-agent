package k8s_watcher

import (
	"context"
	"fmt"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"github.com/puzpuzpuz/xsync"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	addressing "github.com/cilium/cilium/pkg/node/addressing"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
)

type CiliumNodeWatcherParams struct {
	ParentLogger log.Logger
	client.Client
	*runtime.Scheme
	modules.Classifier
	conf.CiliumNodeWatcherConfig
}

type CiliumNodeWatcher struct {
	log.Logger
	ciliumHostAddrs *xsync.MapOf[string, string] // cilium node hash -> cilium host addr
	CiliumNodeWatcherParams
}

func NewCiliumNodeWatcher(params CiliumNodeWatcherParams) (*CiliumNodeWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("cilium_node_watcher")
	if err != nil {
		return nil, err
	}
	return &CiliumNodeWatcher{
		Logger:                  logger,
		ciliumHostAddrs:         xsync.NewMapOf[string](),
		CiliumNodeWatcherParams: params,
	}, nil
}

func (w *CiliumNodeWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cn ciliumv2.CiliumNode
	cnHash := getCiliumNodeHash(req.Name, req.Namespace)
	if err := w.Get(ctx, req.NamespacedName, &cn); err != nil {
		if apierrors.IsNotFound(err) {
			ciliumHostAddr, loaded := w.ciliumHostAddrs.LoadAndDelete(cnHash)
			if !loaded {
				return ctrl.Result{}, nil
			}
			if err := w.UnregisterCiliumHostAddr(ciliumHostAddr); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	//TODO: possibly multiple cilium internal ips?
	var ciliumHostAddr string = ""
	for _, addr := range cn.Spec.Addresses {
		if addr.Type == addressing.NodeCiliumInternalIP {
			ciliumHostAddr = addr.IP
			break
		}
	}
	if ciliumHostAddr == "" {
		return ctrl.Result{}, nil
	}
	w.ciliumHostAddrs.Store(cnHash, ciliumHostAddr)
	if err := w.RegisterCiliumHostAddr(ciliumHostAddr); err != nil {
		return ctrl.Result{}, err
	}
	w.Debugf("cilium host addr %v registered", ciliumHostAddr)
	return ctrl.Result{}, nil
}

func (w *CiliumNodeWatcher) SetupWithManager(mgr ctrl.Manager) error {
	//TODO: configure the event filter
	return ctrl.NewControllerManagedBy(mgr).
		For(&ciliumv2.CiliumNode{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: w.MaxWorker}).
		Complete(w)
}

func getCiliumNodeHash(name, ns string) string {
	return fmt.Sprintf("%s/%s", ns, name)
}
