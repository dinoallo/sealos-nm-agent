package k8s_watcher

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	podlib "github.com/dinoallo/sealos-networkmanager-agent/pkg/pod"
	"github.com/puzpuzpuz/xsync"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

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
	// Each Pod has one tracked Status.PodIP; the workqueue serializes reconciles per key.
	podAddrs *xsync.MapOf[string, string]
	PodWatcherParams
}

func NewPodWatcher(params PodWatcherParams) (*PodWatcher, error) {
	logger, err := params.ParentLogger.WithCompName("pod_watcher")
	if err != nil {
		return nil, err
	}
	return &PodWatcher{
		Logger:           logger,
		podAddrs:         xsync.NewMapOf[string](),
		PodWatcherParams: params,
	}, nil
}

// implements Reconciler
func (w *PodWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	podHash := req.NamespacedName.String()
	if err := w.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, w.unregisterPodAddress(podHash, "")
		}
		return ctrl.Result{}, err
	}
	//TODO: support multiple PodIPs
	addr := pod.Status.PodIP
	if addr == "" {
		return ctrl.Result{}, w.unregisterPodAddress(podHash, "")
	}
	labels := pod.GetLabels()
	podType, podTypeName := podlib.GetPodTypeAndTypeName(ctx, labels)
	podMeta := structs.PodMeta{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Type:      int(podType),
		TypeName:  podTypeName,
		Node:      pod.Status.HostIP,
	}
	if err := w.unregisterPodAddress(podHash, addr); err != nil {
		return ctrl.Result{}, err
	}
	if err := w.RegisterPod(addr, podMeta); err != nil {
		return ctrl.Result{}, err
	}
	w.podAddrs.Store(podHash, addr)
	return ctrl.Result{}, nil
}

func (w *PodWatcher) unregisterPodAddress(podHash, currentAddr string) error {
	oldAddr, loaded := w.podAddrs.Load(podHash)
	if !loaded || oldAddr == currentAddr {
		return nil
	}
	if err := w.UnregisterPod(oldAddr); err != nil {
		return err
	}
	w.podAddrs.Delete(podHash)
	return nil
}

func (w *PodWatcher) SetupWithManager(mgr ctrl.Manager) error {
	//TODO: configure max concurrent reconciles
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(ue event.UpdateEvent) bool {
				oldPod, oldOK := ue.ObjectOld.(*corev1.Pod)
				if !oldOK || oldPod == nil {
					return false
				}
				newPod, newOK := ue.ObjectNew.(*corev1.Pod)
				if !newOK || newPod == nil {
					return false
				}
				return oldPod.Status.PodIP != newPod.Status.PodIP
			},
		}).
		WithOptions(controller.Options{MaxConcurrentReconciles: w.MaxWorker}).
		Complete(w)
}
