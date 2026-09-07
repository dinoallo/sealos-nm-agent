package k8s_watcher

import (
	"context"
	"testing"

	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestServiceExposureChanged(t *testing.T) {
	base := &corev1.Service{
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080)}},
		},
	}
	for _, tc := range []struct {
		name string
		edit func(*corev1.Service)
		want bool
	}{
		{"unchanged", func(*corev1.Service) {}, false},
		{"annotations", func(s *corev1.Service) { s.Annotations = map[string]string{"note": "updated"} }, false},
		{"type", func(s *corev1.Service) { s.Spec.Type = corev1.ServiceTypeNodePort }, true},
		{"target", func(s *corev1.Service) { s.Spec.Ports[0].TargetPort = intstr.FromString("web") }, true},
		{"port", func(s *corev1.Service) { s.Spec.Ports[0].Port = 81 }, true},
		{"name", func(s *corev1.Service) { s.Spec.Ports[0].Name = "web" }, true},
		{"nodeport-number", func(s *corev1.Service) { s.Spec.Ports[0].NodePort = 30080 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updated := base.DeepCopy()
			tc.edit(updated)
			oldObj, err := transformService(base.DeepCopy())
			require.NoError(t, err)
			newObj, err := transformService(updated)
			require.NoError(t, err)
			oldService, ok := oldObj.(client.Object)
			require.True(t, ok)
			newService, ok := newObj.(client.Object)
			require.True(t, ok)
			require.Equal(t, tc.want, serviceExposureChanged(event.UpdateEvent{
				ObjectOld: oldService, ObjectNew: newService,
			}))
		})
	}
}

type nodePortClassifier struct {
	modules.Classifier
	ports map[string]map[uint32]bool
}

func (c *nodePortClassifier) RegisterNodePort(addr string, port uint32) error {
	if c.ports[addr] == nil {
		c.ports[addr] = make(map[uint32]bool)
	}
	c.ports[addr][port] = true
	return nil
}

func (c *nodePortClassifier) UnregisterNodePort(addr string, port uint32) error {
	delete(c.ports[addr], port)
	return nil
}

func TestServiceWatchRefreshesOnlyRelatedEndpointSlices(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, discoveryv1.AddToScheme(scheme))
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}},
		},
	}
	newSlice := func(name, namespace, svc string) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{svcLabelKey: svc}},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses: []string{"10.0.0.2"},
				TargetRef: &corev1.ObjectReference{Name: "pod", Namespace: namespace},
			}},
		}
	}
	one := newSlice("one", "default", "svc")
	two := newSlice("two", "default", "svc")
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&discoveryv1.EndpointSlice{}, endpointSliceServiceIndex, endpointSliceServiceNames).
		WithObjects(service, one, two, newSlice("other-service", "default", "other"),
			newSlice("other-namespace", "other", "svc"), newSlice("unowned", "default", "")).Build()
	classifier := &nodePortClassifier{ports: make(map[string]map[uint32]bool)}
	checker := NewPortExposureChecker(PortExposureCheckerParams{Client: k8sClient, Classifier: classifier})
	w := NewEpWatcher(EpWatcherParams{Client: k8sClient, PortExposureChecker: checker})
	requests := w.endpointSlicesForService(ctx, service)
	require.ElementsMatch(t, []ctrl.Request{
		{NamespacedName: client.ObjectKeyFromObject(one)},
		{NamespacedName: client.ObjectKeyFromObject(two)},
	}, requests)
	for _, serviceType := range []corev1.ServiceType{corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort, corev1.ServiceTypeClusterIP} {
		service.Spec.Type = serviceType
		require.NoError(t, k8sClient.Update(ctx, service))
		// EndpointSlices remain unchanged; only a Service event schedules these reconciles.
		for _, req := range w.endpointSlicesForService(ctx, service) {
			_, err := w.Reconcile(ctx, req)
			require.NoError(t, err)
		}
		require.Equal(t, serviceType == corev1.ServiceTypeNodePort, classifier.ports["10.0.0.2"][8080])
	}
	// A previously unseen Service can find slices that arrived before it.
	unseen := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "default"}}
	require.Equal(t, []ctrl.Request{{NamespacedName: client.ObjectKey{Name: "other-service", Namespace: "default"}}},
		w.endpointSlicesForService(ctx, unseen))
}
