package k8s_watcher

import (
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	podlib "github.com/dinoallo/sealos-networkmanager-agent/pkg/pod"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var cachedPodLabelKeys = []string{
	podlib.CHECK_DB_LABEL_KEY,
	podlib.CHECK_TERMINAL_LABEL_KEY,
	podlib.CHECK_APP_LABEL_KEY,
	podlib.CHECK_JOB_LABEL_KEY,
	podlib.DB_TYPE_LABEL_KEY,
}

func CacheOptions() cache.Options {
	return cache.Options{
		DefaultTransform: stripManagedFields,
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {
				Transform: transformPod,
			},
			&corev1.Service{}: {
				Transform: transformService,
			},
			&discoveryv1.EndpointSlice{}: {
				Transform: transformEndpointSlice,
			},
			&networkingv1.Ingress{}: {
				Transform: transformIngress,
			},
			&ciliumv2.CiliumNode{}: {
				Transform: transformCiliumNode,
			},
		},
	}
}

func stripManagedFields(obj any) (any, error) {
	if object, ok := obj.(metav1.Object); ok {
		object.SetManagedFields(nil)
	}
	return obj, nil
}

func transformPod(obj any) (any, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}

	ports := make([]corev1.ContainerPort, 0)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			ports = append(ports, corev1.ContainerPort{
				Name:          port.Name,
				ContainerPort: port.ContainerPort,
			})
		}
	}
	var containers []corev1.Container
	if len(ports) > 0 {
		containers = []corev1.Container{{Ports: ports}}
	}

	return &corev1.Pod{
		TypeMeta:   pod.TypeMeta,
		ObjectMeta: slimObjectMeta(pod.ObjectMeta, cachedPodLabelKeys...),
		Spec: corev1.PodSpec{
			Containers: containers,
		},
		Status: corev1.PodStatus{
			PodIP:  pod.Status.PodIP,
			HostIP: pod.Status.HostIP,
		},
	}, nil
}

func transformService(obj any) (any, error) {
	service, ok := obj.(*corev1.Service)
	if !ok {
		return obj, nil
	}

	ports := make([]corev1.ServicePort, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		ports = append(ports, corev1.ServicePort{
			Name:       port.Name,
			Port:       port.Port,
			TargetPort: port.TargetPort,
		})
	}
	return &corev1.Service{
		TypeMeta:   service.TypeMeta,
		ObjectMeta: slimObjectMeta(service.ObjectMeta),
		Spec: corev1.ServiceSpec{
			Ports: ports,
			Type:  service.Spec.Type,
		},
	}, nil
}

func transformEndpointSlice(obj any) (any, error) {
	epSlice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return obj, nil
	}

	endpoints := make([]discoveryv1.Endpoint, 0, len(epSlice.Endpoints))
	for _, endpoint := range epSlice.Endpoints {
		slimEndpoint := discoveryv1.Endpoint{
			Addresses: append([]string(nil), endpoint.Addresses...),
		}
		if endpoint.TargetRef != nil {
			slimEndpoint.TargetRef = &corev1.ObjectReference{
				Name:      endpoint.TargetRef.Name,
				Namespace: endpoint.TargetRef.Namespace,
			}
		}
		endpoints = append(endpoints, slimEndpoint)
	}
	return &discoveryv1.EndpointSlice{
		TypeMeta:   epSlice.TypeMeta,
		ObjectMeta: slimObjectMeta(epSlice.ObjectMeta, svcLabelKey),
		Endpoints:  endpoints,
	}, nil
}

func transformIngress(obj any) (any, error) {
	ingress, ok := obj.(*networkingv1.Ingress)
	if !ok {
		return obj, nil
	}

	var defaultBackend *networkingv1.IngressBackend
	if ingress.Spec.DefaultBackend != nil {
		backend := slimIngressBackend(*ingress.Spec.DefaultBackend)
		defaultBackend = &backend
	}

	paths := make([]networkingv1.HTTPIngressPath, 0)
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			paths = append(paths, networkingv1.HTTPIngressPath{
				Backend: slimIngressBackend(path.Backend),
			})
		}
	}
	var rules []networkingv1.IngressRule
	if len(paths) > 0 {
		rules = []networkingv1.IngressRule{{
			IngressRuleValue: networkingv1.IngressRuleValue{
				HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths},
			},
		}}
	}

	return &networkingv1.Ingress{
		TypeMeta:   ingress.TypeMeta,
		ObjectMeta: slimObjectMeta(ingress.ObjectMeta),
		Spec: networkingv1.IngressSpec{
			DefaultBackend: defaultBackend,
			Rules:          rules,
		},
	}, nil
}

func transformCiliumNode(obj any) (any, error) {
	node, ok := obj.(*ciliumv2.CiliumNode)
	if !ok {
		return obj, nil
	}

	addresses := make([]ciliumv2.NodeAddress, 0, len(node.Spec.Addresses))
	for _, address := range node.Spec.Addresses {
		addresses = append(addresses, ciliumv2.NodeAddress{
			Type: address.Type,
			IP:   address.IP,
		})
	}
	return &ciliumv2.CiliumNode{
		TypeMeta:   node.TypeMeta,
		ObjectMeta: slimObjectMeta(node.ObjectMeta),
		Spec: ciliumv2.NodeSpec{
			Addresses: addresses,
		},
	}, nil
}

func slimObjectMeta(meta metav1.ObjectMeta, labelKeys ...string) metav1.ObjectMeta {
	var labels map[string]string
	for _, key := range labelKeys {
		if value, exists := meta.Labels[key]; exists {
			if labels == nil {
				labels = make(map[string]string, len(labelKeys))
			}
			labels[key] = value
		}
	}
	return metav1.ObjectMeta{
		Name:            meta.Name,
		Namespace:       meta.Namespace,
		UID:             meta.UID,
		ResourceVersion: meta.ResourceVersion,
		Generation:      meta.Generation,
		Labels:          labels,
	}
}

func slimIngressBackend(backend networkingv1.IngressBackend) networkingv1.IngressBackend {
	if backend.Service == nil {
		return networkingv1.IngressBackend{}
	}
	return networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: backend.Service.Name,
			Port: backend.Service.Port,
		},
	}
}
