// These are the slim versions of some k8s.io/api resources. Only retain the infomation we need
package k8s_watcher

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type ServicePort struct {
	Name       string
	Port       int32
	TargetPort intstr.IntOrString
}

func NewServicePort(sp corev1.ServicePort) ServicePort {
	return ServicePort{
		Name:       sp.Name,
		Port:       sp.Port,
		TargetPort: sp.TargetPort,
	}
}

type ServiceSpec struct {
	Ports []ServicePort
	Type  corev1.ServiceType
}

func NewServiceSpec(sp corev1.ServiceSpec) ServiceSpec {
	var ports []ServicePort
	for _, _port := range sp.Ports {
		port := NewServicePort(_port)
		ports = append(ports, port)
	}
	return ServiceSpec{
		Ports: ports,
		Type:  sp.Type,
	}
}

type Service struct {
	Name      string
	Namespace string
	Spec      ServiceSpec
}

func NewService(svc corev1.Service) *Service {
	spec := NewServiceSpec(svc.Spec)
	return &Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Spec:      spec,
	}
}

type EndpointSlice struct {
	Name      string
	Namespace string
	Endpoints []Endpoint
}

func NewEndpointSlice(epSlice discoveryv1.EndpointSlice) *EndpointSlice {
	var endpoints []Endpoint
	for _, _ep := range epSlice.Endpoints {
		ep := NewEndpoint(_ep)
		endpoints = append(endpoints, ep)
	}
	return &EndpointSlice{
		Name:      epSlice.Name,
		Namespace: epSlice.Namespace,
		Endpoints: endpoints,
	}
}

type Endpoint struct {
	Addresses []string
	TargetRef *ObjectReference
}

func NewEndpoint(ep discoveryv1.Endpoint) Endpoint {
	var targetRef *ObjectReference
	if ep.TargetRef != nil {
		targetRef = NewObjectReference(*ep.TargetRef)
	}
	return Endpoint{
		Addresses: ep.Addresses,
		TargetRef: targetRef,
	}
}

type ObjectReference struct {
	Namespace string
	Name      string
}

func NewObjectReference(or corev1.ObjectReference) *ObjectReference {
	return &ObjectReference{
		Namespace: or.Namespace,
		Name:      or.Name,
	}
}

type ServiceBackendPort struct {
	Name   string
	Number int32
}

func NewServiceBackendPort(sbp networkingv1.ServiceBackendPort) *ServiceBackendPort {
	return &ServiceBackendPort{
		Name:   sbp.Name,
		Number: sbp.Number,
	}
}

type Ingress struct {
	Name      string
	Namespace string
}

func NewIngress(ingress networkingv1.Ingress) *Ingress {
	return &Ingress{
		Name:      ingress.Name,
		Namespace: ingress.Namespace,
	}
}
