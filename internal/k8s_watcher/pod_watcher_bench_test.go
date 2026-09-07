package k8s_watcher

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	zaplog "github.com/dinoallo/sealos-networkmanager-agent/pkg/log/zap"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Model cache reads without API traffic or retaining classifier state in the benchmark.
type benchmarkPodClient struct {
	client.Client
	pods map[client.ObjectKey]*corev1.Pod
}

func (c benchmarkPodClient) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return fmt.Errorf("expected *corev1.Pod, got %T", obj)
	}
	c.pods[key].DeepCopyInto(pod)
	return nil
}

type benchmarkPodClassifier struct{ modules.Classifier }

func (benchmarkPodClassifier) RegisterPod(string, structs.PodMeta) error { return nil }
func (benchmarkPodClassifier) UnregisterPod(string) error                { return nil }

func benchmarkPodWatcherParams(b testing.TB, count int) (PodWatcherParams, []ctrl.Request) {
	b.Helper()
	logger, err := zaplog.NewZap(false)
	require.NoError(b, err)
	pods := make(map[client.ObjectKey]*corev1.Pod, count)
	requests := make([]ctrl.Request, count)
	for i := range requests {
		key := client.ObjectKey{Namespace: "default", Name: fmt.Sprintf("pod-%d", i)}
		requests[i] = ctrl.Request{NamespacedName: key}
		pods[key] = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Status: corev1.PodStatus{
				PodIP:  fmt.Sprintf("10.0.%d.%d", i/250, i%250+1),
				HostIP: "192.0.2.1",
			},
		}
	}
	return PodWatcherParams{
		ParentLogger: logger,
		Client:       benchmarkPodClient{pods: pods},
		Classifier:   benchmarkPodClassifier{},
	}, requests
}

func BenchmarkPodWatcherReconcile(b *testing.B) {
	params, requests := benchmarkPodWatcherParams(b, 1000)
	ctx := context.Background()
	b.Run("populate-1000", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			watcher, err := NewPodWatcher(params)
			require.NoError(b, err)
			for _, req := range requests {
				_, err = watcher.Reconcile(ctx, req)
				require.NoError(b, err)
			}
		}
	})
	b.Run("unchanged", func(b *testing.B) {
		watcher, err := NewPodWatcher(params)
		require.NoError(b, err)
		_, err = watcher.Reconcile(ctx, requests[0])
		require.NoError(b, err)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = watcher.Reconcile(ctx, requests[0])
			require.NoError(b, err)
		}
	})
}

func BenchmarkPodWatcherRetainedState(b *testing.B) {
	params, requests := benchmarkPodWatcherParams(b, 10000)
	ctx := context.Background()
	var retained int64
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		watcher, err := NewPodWatcher(params)
		require.NoError(b, err)
		for _, req := range requests {
			_, err = watcher.Reconcile(ctx, req)
			require.NoError(b, err)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(watcher)
		retained += int64(after.HeapAlloc) - int64(before.HeapAlloc)
	}
	b.ReportMetric(float64(retained)/float64(b.N)/float64(len(requests)), "live-B/pod")
}
