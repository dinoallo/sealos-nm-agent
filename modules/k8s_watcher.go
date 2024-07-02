package modules

import (
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

type PortExposureChecker interface {
	UpdateIngress(newIngress networkingv1.Ingress) error
	RemoveIngress(hash string) error
	UpdateEpSlice(newEpSlice discoveryv1.EndpointSlice) error
	RemoveEpSlice(hash string) error
}
