package k8s_watcher

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func getForwardingPortByNumber(service Service, portNumber int32) intstr.IntOrString {
	for _, svcPort := range service.Spec.Ports {
		if svcPort.Port == portNumber {
			if svcPort.TargetPort.IntVal != 0 || svcPort.TargetPort.StrVal != "" {
				return svcPort.TargetPort
			} else {
				return intstr.FromInt32(svcPort.Port)
			}
		}
	}
	return intstr.IntOrString{}
}

func getForwardingPortByName(service Service, portName string) intstr.IntOrString {
	for _, svcPort := range service.Spec.Ports {
		if svcPort.Name == portName {
			if svcPort.TargetPort.IntVal != 0 || svcPort.TargetPort.StrVal != "" {
				return svcPort.TargetPort
			} else {
				return intstr.FromInt32(svcPort.Port)
			}
		}
	}
	return intstr.IntOrString{}
}

func getBackends(ingress networkingv1.Ingress) ([]networkingv1.IngressBackend, error) {
	backends := []networkingv1.IngressBackend{}
	ingressSpec := ingress.Spec
	defaultBackend := ingressSpec.DefaultBackend
	if defaultBackend != nil {
		backends = append(backends, *defaultBackend)
	}
	rules := ingressSpec.Rules
	for _, rule := range rules {
		httpRuleValue := rule.IngressRuleValue.HTTP
		if httpRuleValue != nil {
			paths := httpRuleValue.Paths
			for _, path := range paths {
				backends = append(backends, path.Backend)
			}
		}
	}
	return backends, nil
}

func getNamedPort(pod corev1.Pod, portName string) (int32, bool) {
	for _, container := range pod.Spec.Containers {
		for _, containerPort := range container.Ports {
			if containerPort.Name == portName {
				portNumber := containerPort.ContainerPort
				return portNumber, true
			}
		}
	}
	return 0, false
}

func GetIngressHash(ingressName, ingressNamespace string) string {
	return fmt.Sprintf("%s/%s", ingressNamespace, ingressName)
}

func GetIBHash(svcHash string, sbp networkingv1.ServiceBackendPort) string {
	if sbp.Name != "" {
		return fmt.Sprintf("%s/portName/%s", svcHash, sbp.Name)
	} else {
		return fmt.Sprintf("%s/portName/%v", svcHash, sbp.Number)
	}
}

func GetEpSliceHash(epSliceName, epSliceNamespace string) string {
	return fmt.Sprintf("%s/%s", epSliceNamespace, epSliceName)
}

func GetServiceHash(svcName, svcNamespace string) string {
	return fmt.Sprintf("%s/%s", svcNamespace, svcName)
}

func GetPodHash(podName, podNamespace string) string {
	return fmt.Sprintf("%s/%s", podNamespace, podName)
}
