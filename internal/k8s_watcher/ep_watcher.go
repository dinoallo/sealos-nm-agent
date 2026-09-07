package k8s_watcher

import (
	"context"
	"fmt"
	"reflect"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
)

const endpointSliceServiceIndex = "endpointSliceService"

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
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &discoveryv1.EndpointSlice{}, endpointSliceServiceIndex, endpointSliceServiceNames); err != nil {
		return fmt.Errorf("index EndpointSlices by Service: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&discoveryv1.EndpointSlice{}).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(w.endpointSlicesForService),
			builder.WithPredicates(predicate.Funcs{UpdateFunc: serviceExposureChanged})).
		WithOptions(controller.Options{MaxConcurrentReconciles: w.MaxWorker}).
		Complete(w)
}

func endpointSliceServiceNames(obj client.Object) []string {
	if name := obj.GetLabels()[svcLabelKey]; name != "" {
		return []string{name}
	}
	return nil
}

func (w *EpWatcher) endpointSlicesForService(ctx context.Context, obj client.Object) []ctrl.Request {
	var slices discoveryv1.EndpointSliceList
	if err := w.List(ctx, &slices, client.InNamespace(obj.GetNamespace()),
		client.MatchingFields{endpointSliceServiceIndex: obj.GetName()}); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to find EndpointSlices for Service", "service", client.ObjectKeyFromObject(obj))
		return nil
	}
	requests := make([]ctrl.Request, 0, len(slices.Items))
	for i := range slices.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&slices.Items[i])})
	}
	return requests
}

func serviceExposureChanged(e event.UpdateEvent) bool {
	oldService, oldOK := e.ObjectOld.(*corev1.Service)
	newService, newOK := e.ObjectNew.(*corev1.Service)
	if !oldOK || !newOK || oldService == nil || newService == nil {
		return false
	}
	// The Service cache transform retains only the port fields used by the checker.
	return oldService.Spec.Type != newService.Spec.Type ||
		!reflect.DeepEqual(oldService.Spec.Ports, newService.Spec.Ports)
}
