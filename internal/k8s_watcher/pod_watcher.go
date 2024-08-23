package k8s_watcher

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/puzpuzpuz/xsync"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	podlib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/pod"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type podAddrTable struct {
	podAddrs *xsync.MapOf[string, struct{}]
}

func newPodAddrTable() *podAddrTable {
	return &podAddrTable{
		podAddrs: xsync.NewMapOf[struct{}](),
	}
}

// TODO: add logger
type PodWatcherParams struct {
	ParentLogger log.Logger
	client.Client
	*runtime.Scheme
	modules.Classifier
	conf.PodWatcherConfig
}

type PodWatcher struct {
	log.Logger
	podAddrTables *xsync.MapOf[string, *podAddrTable]
	PodWatcherParams
}

func NewPodWatcher(params PodWatcherParams) (*PodWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("pod_watcher")
	if err != nil {
		return nil, err
	}
	return &PodWatcher{
		Logger:           logger,
		podAddrTables:    xsync.NewMapOf[*podAddrTable](),
		PodWatcherParams: params,
	}, nil
}

// implements Reconciler
func (w *PodWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	podHash := req.NamespacedName.String()
	if err := w.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			pat, loaded := w.podAddrTables.LoadAndDelete(podHash)
			if !loaded {
				return ctrl.Result{}, nil
			}
			unregister := func(podAddr string, v struct{}) bool {
				if err := w.UnregisterPod(podAddr); err != nil {
					//TODO: handle me
					return true
				}
				pat.podAddrs.Delete(podAddr)
				return true
			}
			pat.podAddrs.Range(unregister)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	//TODO: support multiple PodIPs
	addr := pod.Status.PodIP
	labels := pod.GetLabels()
	podType, podTypeName := podlib.GetPodTypeAndTypeName(ctx, labels)
	podMeta := structs.PodMeta{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Type:      int(podType),
		TypeName:  podTypeName,
		Node:      pod.Status.HostIP,
	}
	newPAT := newPodAddrTable()
	pat, loaded := w.podAddrTables.LoadOrStore(podHash, newPAT)
	if !loaded {
		pat = newPAT
	}
	pat.podAddrs.Store(addr, struct{}{})
	if err := w.RegisterPod(addr, podMeta); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (w *PodWatcher) SetupWithManager(mgr ctrl.Manager) error {
	//TODO: configure max concurrent reconciles
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(ue event.UpdateEvent) bool {
				oldPod := ue.ObjectOld.(*corev1.Pod)
				newPod := ue.ObjectNew.(*corev1.Pod)
				if oldPod.Status.PodIP != newPod.Status.PodIP {
					return true
				}
				return false
			},
		}).
		WithOptions(controller.Options{MaxConcurrentReconciles: w.MaxWorker}).
		Complete(w)
}
