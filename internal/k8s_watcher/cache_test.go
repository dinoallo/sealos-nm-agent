package k8s_watcher

import (
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	addressing "github.com/cilium/cilium/pkg/node/addressing"
	podlib "github.com/dinoallo/sealos-networkmanager-agent/pkg/pod"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTransformPodKeepsOnlyWatcherFields(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pod",
			Namespace:       "default",
			ResourceVersion: "42",
			Labels: map[string]string{
				podlib.CHECK_APP_LABEL_KEY: "app-name",
				"unused":                   "large-value",
			},
			Annotations:   map[string]string{"large": "value"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "manager"}},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "container",
				Image: "large-image-name",
				Ports: []corev1.ContainerPort{{
					Name:          "http",
					ContainerPort: 8080,
					Protocol:      corev1.ProtocolUDP,
				}},
			}},
			Volumes: []corev1.Volume{{Name: "large-volume"}},
		},
		Status: corev1.PodStatus{
			PodIP:             "10.0.0.2",
			HostIP:            "10.0.0.1",
			ContainerStatuses: []corev1.ContainerStatus{{Name: "container", Image: "large-image-name"}},
		},
	}

	transformed, err := transformPod(pod)
	require.NoError(t, err)
	slim := transformed.(*corev1.Pod)

	assert.Equal(t, "10.0.0.2", slim.Status.PodIP)
	assert.Equal(t, "10.0.0.1", slim.Status.HostIP)
	assert.Equal(t, "app-name", slim.Labels[podlib.CHECK_APP_LABEL_KEY])
	assert.NotContains(t, slim.Labels, "unused")
	assert.Equal(t, int32(8080), slim.Spec.Containers[0].Ports[0].ContainerPort)
	assert.Empty(t, slim.Spec.Containers[0].Image)
	assert.Empty(t, slim.Spec.Volumes)
	assert.Empty(t, slim.Status.ContainerStatuses)
	assert.Nil(t, slim.Annotations)
	assert.Nil(t, slim.ManagedFields)
}

func TestTransformServiceAndEndpointSliceKeepExposureFields(t *testing.T) {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeNodePort,
			ClusterIP: "10.96.0.1",
			Selector:  map[string]string{"large": "value"},
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Port:       80,
				TargetPort: intstr.FromString("web"),
				NodePort:   30080,
			}},
		},
	}
	transformed, err := transformService(service)
	require.NoError(t, err)
	slimService := transformed.(*corev1.Service)
	assert.Equal(t, corev1.ServiceTypeNodePort, slimService.Spec.Type)
	assert.Equal(t, intstr.FromString("web"), slimService.Spec.Ports[0].TargetPort)
	assert.Empty(t, slimService.Spec.ClusterIP)
	assert.Nil(t, slimService.Spec.Selector)
	assert.Zero(t, slimService.Spec.Ports[0].NodePort)

	epSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "slice",
			Namespace: "default",
			Labels: map[string]string{
				svcLabelKey: "svc",
				"unused":    "large-value",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.2"},
			TargetRef: &corev1.ObjectReference{
				Kind:      "Pod",
				Name:      "pod",
				Namespace: "default",
				UID:       "unused-uid",
			},
			Hostname: pointer("unused-hostname"),
		}},
		Ports: []discoveryv1.EndpointPort{{Name: pointer("unused-port")}},
	}
	transformed, err = transformEndpointSlice(epSlice)
	require.NoError(t, err)
	slimSlice := transformed.(*discoveryv1.EndpointSlice)
	assert.Equal(t, "svc", slimSlice.Labels[svcLabelKey])
	assert.NotContains(t, slimSlice.Labels, "unused")
	assert.Equal(t, []string{"10.0.0.2"}, slimSlice.Endpoints[0].Addresses)
	assert.Equal(t, "pod", slimSlice.Endpoints[0].TargetRef.Name)
	assert.Empty(t, slimSlice.Endpoints[0].TargetRef.Kind)
	assert.Nil(t, slimSlice.Endpoints[0].Hostname)
	assert.Empty(t, slimSlice.Ports)
}

func TestTransformIngressAndCiliumNodeKeepWatcherFields(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "default"},
		Spec: networkingv1.IngressSpec{
			IngressClassName: pointer("large-class-name"),
			TLS:              []networkingv1.IngressTLS{{SecretName: "large-secret"}},
			Rules: []networkingv1.IngressRule{{
				Host: "large.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path: "/large-path",
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "svc",
									Port: networkingv1.ServiceBackendPort{Number: 80},
								},
							},
						}},
					},
				},
			}},
		},
	}
	transformed, err := transformIngress(ingress)
	require.NoError(t, err)
	slimIngress := transformed.(*networkingv1.Ingress)
	require.Len(t, slimIngress.Spec.Rules, 1)
	backend := slimIngress.Spec.Rules[0].HTTP.Paths[0].Backend
	require.NotNil(t, backend.Service)
	assert.Equal(t, "svc", backend.Service.Name)
	assert.Equal(t, int32(80), backend.Service.Port.Number)
	assert.Empty(t, slimIngress.Spec.Rules[0].Host)
	assert.Empty(t, slimIngress.Spec.Rules[0].HTTP.Paths[0].Path)
	assert.Nil(t, slimIngress.Spec.IngressClassName)
	assert.Empty(t, slimIngress.Spec.TLS)

	node := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "node",
			Annotations:   map[string]string{"large": "value"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "manager"}},
		},
		Spec: ciliumv2.NodeSpec{
			Addresses: []ciliumv2.NodeAddress{{
				Type: addressing.NodeCiliumInternalIP,
				IP:   "10.0.0.3",
			}},
		},
		Status: ciliumv2.NodeStatus{},
	}
	transformed, err = transformCiliumNode(node)
	require.NoError(t, err)
	slimNode := transformed.(*ciliumv2.CiliumNode)
	require.Len(t, slimNode.Spec.Addresses, 1)
	assert.Equal(t, addressing.NodeCiliumInternalIP, slimNode.Spec.Addresses[0].Type)
	assert.Equal(t, "10.0.0.3", slimNode.Spec.Addresses[0].IP)
	assert.Nil(t, slimNode.Annotations)
	assert.Nil(t, slimNode.ManagedFields)
}

func pointer[T any](value T) *T {
	return &value
}
