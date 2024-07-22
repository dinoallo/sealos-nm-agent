package k8s_watcher

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	networkingv1 "k8s.io/api/networking/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

type IngressWatcherParams struct {
	client.Client
	*runtime.Scheme
	modules.PortExposureChecker
	conf.IngressWatcherConfig
}

type IngressWatcher struct {
	IngressWatcherParams
}

func NewIngressWatcher(params IngressWatcherParams) *IngressWatcher {
	return &IngressWatcher{
		IngressWatcherParams: params,
	}
}

func (w *IngressWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ingress networkingv1.Ingress
	ingressHash := GetIngressHash(req.Name, req.Namespace)
	if err := w.Get(ctx, req.NamespacedName, &ingress); err != nil {
		if apierrors.IsNotFound(err) {
			if err := w.RemoveIngress(ingressHash); err != nil {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if err := w.UpdateIngress(ingress); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (w *IngressWatcher) SetupWithManager(mgr ctrl.Manager) error {
	//TODO: configure max concurrent reconciles
	//TODO: configure the event filter
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: w.MaxWorker}).
		Complete(w)
}
