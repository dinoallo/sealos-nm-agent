package k8s_watcher

import (
	"context"

	cv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type CepWatcherParams struct {
	ParentLogger log.Logger
	Host         string
	client.Client
	*runtime.Scheme
	modules.BPFTrafficFactory
	conf.CepWatcherConfig
}

type CepWatcher struct {
	log.Logger
	CepWatcherParams
}

func NewCepWatcher(params CepWatcherParams) (*CepWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("cep_watcher")
	if err != nil {
		return nil, modules.ErrCreatingLogger
	}
	return &CepWatcher{
		Logger:           logger,
		CepWatcherParams: params,
	}, nil
}

func (w *CepWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cep cv2.CiliumEndpoint
	cepHash := GetCepHash(req.Name, req.Namespace)
	if err := w.Get(ctx, req.NamespacedName, &cep); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		w.Errorf("unable to get the cilium endpoint: %v", err)
		return ctrl.Result{}, err
	}
	eid := cep.Status.ID
	// if cep.Status.Networking != nil && cep.Status.Networking.NodeIP != w.Host {
	// 	w.Debugf("cilium endpoint %v is not on this host(%v). skip it...", eid, w.Host)
	// 	return ctrl.Result{}, nil
	// }
	if err := w.SubscribeToCep(eid); err != nil {
		w.Errorf("failed to subscribe to cep %v: %v", cepHash, err)
		return ctrl.Result{}, err
	}
	w.Infof("cep %v subscribed", cepHash)
	return ctrl.Result{}, nil
}

func (w *CepWatcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv2.CiliumEndpoint{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(ce event.CreateEvent) bool {
				ep := ce.Object.(*cv2.CiliumEndpoint)
				if ep.Status.State != "ready" {
					return false
				}
				if ep.Status.Networking != nil && ep.Status.Networking.NodeIP == w.Host {
					return true
				}
				return false
			},
			UpdateFunc: func(ue event.UpdateEvent) bool {
				oldEp := ue.ObjectOld.(*cv2.CiliumEndpoint)
				newEp := ue.ObjectNew.(*cv2.CiliumEndpoint)
				if newEp.Status.State != "ready" {
					return false
				}
				if newEp.Status.Networking == nil || newEp.Status.Networking.NodeIP != w.Host {
					return false
				}
				if oldEp.Status.ID != newEp.Status.ID {
					return true
				}
				return false
			},
			DeleteFunc: func(de event.DeleteEvent) bool { return false },
		}).
		WithOptions(controller.Options{MaxConcurrentReconciles: w.MaxWorker}).
		Complete(w)
}
