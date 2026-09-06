package k8s_watcher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/puzpuzpuz/xsync"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type retryingPodClassifier struct {
	*recordingClassifier
	registerErr   error
	unregisterErr error
	unregistered  []string
}

func (c *retryingPodClassifier) RegisterPod(addr string, meta structs.PodMeta) error {
	if c.registerErr != nil {
		return c.registerErr
	}
	return c.recordingClassifier.RegisterPod(addr, meta)
}

func (c *retryingPodClassifier) UnregisterPod(addr string) error {
	c.unregistered = append(c.unregistered, addr)
	if c.unregisterErr != nil {
		return c.unregisterErr
	}
	return c.recordingClassifier.UnregisterPod(addr)
}

func newRetryingPodWatcher(t *testing.T) (*PodWatcher, *retryingPodClassifier, ctrl.Request) {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.2", HostIP: "192.0.2.1"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}).WithObjects(pod).Build()
	classifier := &retryingPodClassifier{recordingClassifier: newRecordingClassifier()}
	watcher := &PodWatcher{
		podAddrs: xsync.NewMapOf[string](),
		PodWatcherParams: PodWatcherParams{
			Client: k8sClient, Classifier: classifier,
		},
	}
	return watcher, classifier, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)}
}

func TestPodWatcherRetriesAddressChange(t *testing.T) {
	ctx := context.Background()
	w, classifier, req := newRetryingPodWatcher(t)
	failure := errors.New("classifier unavailable")

	classifier.registerErr = failure
	_, err := w.Reconcile(ctx, req)
	require.ErrorIs(t, err, failure)
	require.False(t, classifier.hasPod("10.0.0.2"))
	require.Zero(t, w.podAddrs.Size())

	classifier.registerErr = nil
	_, err = w.Reconcile(ctx, req)
	require.NoError(t, err)
	require.True(t, classifier.hasPod("10.0.0.2"))

	updatePodIP(t, w.Client, req.NamespacedName, "10.0.0.3")
	classifier.unregisterErr = failure
	_, err = w.Reconcile(ctx, req)
	require.ErrorIs(t, err, failure)
	require.True(t, classifier.hasPod("10.0.0.2"))
	require.False(t, classifier.hasPod("10.0.0.3"))
	addr, tracked := w.podAddrs.Load(req.NamespacedName.String())
	require.True(t, tracked)
	require.Equal(t, "10.0.0.2", addr)

	classifier.unregisterErr = nil
	classifier.registerErr = failure
	_, err = w.Reconcile(ctx, req)
	require.ErrorIs(t, err, failure)
	require.False(t, classifier.hasPod("10.0.0.2"))
	require.False(t, classifier.hasPod("10.0.0.3"))
	require.Zero(t, w.podAddrs.Size())

	classifier.registerErr = nil
	_, err = w.Reconcile(ctx, req)
	require.NoError(t, err)
	require.True(t, classifier.hasPod("10.0.0.3"))
	require.Equal(t, []string{"10.0.0.2", "10.0.0.2"}, classifier.unregistered)

	// An unchanged address must not clear classifier port state by unregistering it.
	_, err = w.Reconcile(ctx, req)
	require.NoError(t, err)
	require.Len(t, classifier.unregistered, 2)
	require.Equal(t, 1, w.podAddrs.Size())
}

func TestPodWatcherRetriesAddressRemoval(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(fmt.Sprintf("deleted=%t", deleted), func(t *testing.T) {
			ctx := context.Background()
			w, classifier, req := newRetryingPodWatcher(t)
			_, err := w.Reconcile(ctx, req)
			require.NoError(t, err)
			if deleted {
				require.NoError(t, w.Delete(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: req.Name, Namespace: req.Namespace},
				}))
			} else {
				updatePodIP(t, w.Client, req.NamespacedName, "")
			}
			failure := errors.New("classifier unavailable")
			classifier.unregisterErr = failure
			_, err = w.Reconcile(ctx, req)
			require.ErrorIs(t, err, failure)
			require.True(t, classifier.hasPod("10.0.0.2"))
			require.Equal(t, 1, w.podAddrs.Size())

			classifier.unregisterErr = nil
			_, err = w.Reconcile(ctx, req)
			require.NoError(t, err)
			require.False(t, classifier.hasPod("10.0.0.2"))
			require.Zero(t, w.podAddrs.Size())
			_, err = w.Reconcile(ctx, req)
			require.NoError(t, err)
			require.Len(t, classifier.unregistered, 2)
		})
	}
}

func TestPodWatcherConcurrentKeys(t *testing.T) {
	params, requests := benchmarkPodWatcherParams(t, 100)
	classifier := newRecordingClassifier()
	params.Classifier = classifier
	w, err := NewPodWatcher(params)
	require.NoError(t, err)
	errs := make(chan error, len(requests))
	var wg sync.WaitGroup
	for _, req := range requests {
		wg.Add(1)
		go func(req ctrl.Request) {
			defer wg.Done()
			_, err := w.Reconcile(context.Background(), req)
			errs <- err
		}(req)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, len(requests), w.podAddrs.Size())
	require.Len(t, classifier.pods, len(requests))
}
