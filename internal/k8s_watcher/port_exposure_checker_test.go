package k8s_watcher

import (
	"testing"

	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/puzpuzpuz/xsync"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func newTestPortExposureChecker() *PortExposureChecker {
	return NewPortExposureChecker(PortExposureCheckerParams{
		Classifier: mock.NewDummyClassifier(mock.DummyClassifierConfig{}),
	})
}

func TestRemoveEpSliceSkipsNilOwner(t *testing.T) {
	checker := newTestPortExposureChecker()
	esHash := GetEpSliceHash("slice", "default")
	checker.epSlices.Store(esHash, &ES{
		epSlice: &EndpointSlice{Name: "slice", Namespace: "default"},
	})

	require.NoError(t, checker.RemoveEpSlice(esHash))
}

func TestRemoveEpSliceSkipsNilOwnerService(t *testing.T) {
	checker := newTestPortExposureChecker()
	esHash := GetEpSliceHash("slice", "default")
	checker.epSlices.Store(esHash, &ES{
		epSlice: &EndpointSlice{Name: "slice", Namespace: "default"},
		ownedBy: &SVC{
			epSlices:     xsync.NewMapOf[*ES](),
			referencedBy: xsync.NewMapOf[*IB](),
		},
	})

	require.NoError(t, checker.RemoveEpSlice(esHash))
}

func TestRemoveIngressBackendSkipsNilBackend(t *testing.T) {
	checker := newTestPortExposureChecker()
	ibHash := GetIBHash(GetServiceHash("svc", "default"), networkingv1.ServiceBackendPort{})
	checker.ibs.Store(ibHash, &IB{
		svcHash:      GetServiceHash("svc", "default"),
		referencedBy: xsync.NewMapOf[*I](),
	})

	checker.removeIngressBackend(ibHash)
}

func TestDerefIngressBackendsSkipsNilBackendEntry(t *testing.T) {
	checker := newTestPortExposureChecker()
	ingressHash := GetIngressHash("ingress", "default")
	ibHash := GetIBHash(GetServiceHash("svc", "default"), networkingv1.ServiceBackendPort{})
	i := NewI(networkingv1.Ingress{})
	i.backends.Store(ibHash, nil)

	checker.derefIngressBackends(ingressHash, i)
}

func TestUpdateServiceInitializesNilReferenceMaps(t *testing.T) {
	checker := newTestPortExposureChecker()
	svcHash := GetServiceHash("svc", "default")
	checker.services.Store(svcHash, &SVC{})

	svc, err := checker.updateService(svcHash, corev1.Service{})
	require.NoError(t, err)
	require.NotNil(t, svc.epSlices)
	require.NotNil(t, svc.referencedBy)
}

func TestUpdateExposureForIngressBackendSkipsNilPointers(t *testing.T) {
	checker := newTestPortExposureChecker()

	require.NoError(t, checker.updateExposureForIngressBackend(&IB{}, true))

	require.NoError(t, checker.updateExposureForIngressBackend(&IB{
		backend: &SVC{
			epSlices:     xsync.NewMapOf[*ES](),
			referencedBy: xsync.NewMapOf[*IB](),
		},
	}, true))
}

func TestUpdateExposureForIngressBackendSkipsNilEndpointSlice(t *testing.T) {
	checker := newTestPortExposureChecker()
	svc := &SVC{
		service: &Service{
			Name:      "svc",
			Namespace: "default",
			Spec: ServiceSpec{
				Ports: []ServicePort{{Port: 80}},
			},
		},
		epSlices:     xsync.NewMapOf[*ES](),
		referencedBy: xsync.NewMapOf[*IB](),
	}
	svc.epSlices.Store(GetEpSliceHash("slice", "default"), &ES{})

	require.NoError(t, checker.updateExposureForIngressBackend(&IB{
		sbp:     &ServiceBackendPort{Number: 80},
		backend: svc,
	}, true))
}
