package k8s_watcher

import (
	"context"
	"sync"
	"testing"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	addressing "github.com/cilium/cilium/pkg/node/addressing"
	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	zaplog "github.com/dinoallo/sealos-networkmanager-agent/pkg/log/zap"
	"github.com/puzpuzpuz/xsync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type recordingClassifier struct {
	modules.Classifier

	mu          sync.Mutex
	pods        map[string]structs.PodMeta
	ciliumAddrs map[string]struct{}
}

func newRecordingClassifier() *recordingClassifier {
	return &recordingClassifier{
		pods:        make(map[string]structs.PodMeta),
		ciliumAddrs: make(map[string]struct{}),
	}
}

func (c *recordingClassifier) RegisterPod(addr string, meta structs.PodMeta) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pods[addr] = meta
	return nil
}

func (c *recordingClassifier) UnregisterPod(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pods, addr)
	return nil
}

func (c *recordingClassifier) RegisterCiliumHostAddr(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ciliumAddrs[addr] = struct{}{}
	return nil
}

func (c *recordingClassifier) UnregisterCiliumHostAddr(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ciliumAddrs, addr)
	return nil
}

func (c *recordingClassifier) hasPod(addr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, exists := c.pods[addr]
	return exists
}

func (c *recordingClassifier) hasCiliumAddr(addr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, exists := c.ciliumAddrs[addr]
	return exists
}

func TestPodWatcherRemovesPreviousAndEmptyAddresses(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.2", HostIP: "10.0.0.1"},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}).
		WithObjects(pod).
		Build()
	classifier := newRecordingClassifier()
	watcher := &PodWatcher{
		podAddrs: xsync.NewMapOf[string](),
		PodWatcherParams: PodWatcherParams{
			Client:     k8sClient,
			Scheme:     scheme,
			Classifier: classifier,
		},
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)}

	_, err := watcher.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, classifier.hasPod("10.0.0.2"))

	updatePodIP(t, k8sClient, req.NamespacedName, "10.0.0.3")
	_, err = watcher.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, classifier.hasPod("10.0.0.2"))
	assert.True(t, classifier.hasPod("10.0.0.3"))

	updatePodIP(t, k8sClient, req.NamespacedName, "")
	_, err = watcher.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, classifier.hasPod(""))
	assert.False(t, classifier.hasPod("10.0.0.3"))
	_, tracked := watcher.podAddrs.Load(req.NamespacedName.String())
	assert.False(t, tracked)
}

func TestCiliumNodeWatcherRemovesPreviousAndEmptyAddresses(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, ciliumv2.AddToScheme(scheme))
	node := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node"},
		Spec: ciliumv2.NodeSpec{
			Addresses: []ciliumv2.NodeAddress{{
				Type: addressing.NodeCiliumInternalIP,
				IP:   "10.0.0.2",
			}},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()
	classifier := newRecordingClassifier()
	logger, err := zaplog.NewZap(false)
	require.NoError(t, err)
	watcher, err := NewCiliumNodeWatcher(CiliumNodeWatcherParams{
		ParentLogger:            logger,
		Client:                  k8sClient,
		Scheme:                  scheme,
		Classifier:              classifier,
		CiliumNodeWatcherConfig: conf.NewCiliumNodeWatcherConfig(),
	})
	require.NoError(t, err)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(node)}

	_, err = watcher.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, classifier.hasCiliumAddr("10.0.0.2"))

	updateCiliumAddress(t, k8sClient, req.NamespacedName, "10.0.0.3")
	_, err = watcher.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, classifier.hasCiliumAddr("10.0.0.2"))
	assert.True(t, classifier.hasCiliumAddr("10.0.0.3"))

	updateCiliumAddress(t, k8sClient, req.NamespacedName, "")
	_, err = watcher.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, classifier.hasCiliumAddr("10.0.0.3"))
	_, tracked := watcher.ciliumHostAddrs.Load(getCiliumNodeHash("node", ""))
	assert.False(t, tracked)
}

func updatePodIP(t *testing.T, k8sClient client.Client, key types.NamespacedName, addr string) {
	t.Helper()
	var pod corev1.Pod
	require.NoError(t, k8sClient.Get(context.Background(), key, &pod))
	pod.Status.PodIP = addr
	require.NoError(t, k8sClient.Status().Update(context.Background(), &pod))
}

func updateCiliumAddress(t *testing.T, k8sClient client.Client, key types.NamespacedName, addr string) {
	t.Helper()
	var node ciliumv2.CiliumNode
	require.NoError(t, k8sClient.Get(context.Background(), key, &node))
	if addr == "" {
		node.Spec.Addresses = nil
	} else {
		node.Spec.Addresses = []ciliumv2.NodeAddress{{
			Type: addressing.NodeCiliumInternalIP,
			IP:   addr,
		}}
	}
	require.NoError(t, k8sClient.Update(context.Background(), &node))
}
