package k8s_watcher

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
)

type EpWatcherParams struct {
	client.Client
	*runtime.Scheme
	modules.PortExposureChecker
	conf.EpWatcherConfig
}

type EpWatcher struct {
	EpWatcherParams
}

func NewEpWatcher(params EpWatcherParams) *EpWatcher {
	return &EpWatcher{
		EpWatcherParams: params,
	}
}

func (w *EpWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var epSlice discoveryv1.EndpointSlice
	epSliceHash := GetEpSliceHash(req.Name, req.Namespace)
	if err := w.Get(ctx, req.NamespacedName, &epSlice); err != nil {
		if apierrors.IsNotFound(err) {
			if err := w.RemoveEpSlice(epSliceHash); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if err := w.UpdateEpSlice(epSlice); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (w *EpWatcher) SetupWithManager(mgr ctrl.Manager) error {
	//TODO: configure the event filter
	return ctrl.NewControllerManagedBy(mgr).
		For(&discoveryv1.EndpointSlice{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: w.MaxWorker}).
		Complete(w)
}
