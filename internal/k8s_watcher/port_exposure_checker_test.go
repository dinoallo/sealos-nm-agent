package k8s_watcher

import (
	"errors"
	"testing"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/puzpuzpuz/xsync"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var errClassifierUpdate = errors.New("classifier update failed")

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

func TestUpdateIngressBackendReturnsExposureError(t *testing.T) {
	checker := newFailingExposureChecker()
	svcHash := GetServiceHash("svc", "default")
	svc := NewSVC(corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}},
		},
	})
	svc.epSlices.Store(GetEpSliceHash("slice", "default"), NewES(svc, discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "slice", Namespace: "default"},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.2"},
			TargetRef: &corev1.ObjectReference{Name: "pod", Namespace: "default"},
		}},
	}))
	checker.services.Store(svcHash, svc)

	_, err := checker.updateIngressBackend(svcHash, networkingv1.ServiceBackendPort{Number: 80})
	require.ErrorIs(t, err, errClassifierUpdate)
}

func TestRemoveIngressBackendPreservesStateOnExposureError(t *testing.T) {
	checker := newFailingExposureChecker()
	svcHash := GetServiceHash("svc", "default")
	ibHash, svc, ib := storeExposedBackend(checker, svcHash)

	err := checker.removeIngressBackend(ibHash)
	require.ErrorIs(t, err, errClassifierUpdate)

	loadedIB, loaded := checker.ibs.Load(ibHash)
	require.True(t, loaded)
	require.Same(t, ib, loadedIB)
	_, referenced := svc.referencedBy.Load(ibHash)
	require.True(t, referenced)
}

func TestRemoveEpSlicePreservesStateOnExposureError(t *testing.T) {
	checker := newFailingExposureChecker()
	svcHash := GetServiceHash("svc", "default")
	_, svc, _ := storeExposedBackend(checker, svcHash)
	esHash := GetEpSliceHash("slice", "default")

	err := checker.removeEpSlice(esHash)
	require.ErrorIs(t, err, errClassifierUpdate)

	_, loaded := checker.epSlices.Load(esHash)
	require.True(t, loaded)
	_, referencedBySvc := svc.epSlices.Load(esHash)
	require.True(t, referencedBySvc)
}

func newFailingExposureChecker() *PortExposureChecker {
	return NewPortExposureChecker(PortExposureCheckerParams{
		Classifier: failingExposureClassifier{},
	})
}

func storeExposedBackend(checker *PortExposureChecker, svcHash string) (string, *SVC, *IB) {
	svc := NewSVC(corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}},
		},
	})
	esHash := GetEpSliceHash("slice", "default")
	es := NewES(svc, discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "slice", Namespace: "default"},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.2"},
			TargetRef: &corev1.ObjectReference{Name: "pod", Namespace: "default"},
		}},
	})
	ib := NewIB(svcHash, networkingv1.ServiceBackendPort{Number: 80})
	ib.backend = svc
	ibHash := GetIBHash(svcHash, networkingv1.ServiceBackendPort{Number: 80})

	checker.services.Store(svcHash, svc)
	checker.epSlices.Store(esHash, es)
	checker.ibs.Store(ibHash, ib)
	svc.epSlices.Store(esHash, es)
	svc.referencedBy.Store(ibHash, ib)
	return ibHash, svc, ib
}

type failingExposureClassifier struct{}

func (failingExposureClassifier) RegisterPod(string, structs.PodMeta) error { return nil }
func (failingExposureClassifier) UnregisterPod(string) error                { return nil }
func (failingExposureClassifier) RegisterExposedPort(string, uint32) error {
	return errClassifierUpdate
}
func (failingExposureClassifier) UnregisterExposedPort(string, uint32) error {
	return errClassifierUpdate
}
func (failingExposureClassifier) RegisterNodePort(string, uint32) error {
	return errClassifierUpdate
}
func (failingExposureClassifier) UnregisterNodePort(string, uint32) error {
	return errClassifierUpdate
}
func (failingExposureClassifier) RegisterHostAddr(string) error         { return nil }
func (failingExposureClassifier) UnregisterHostAddr(string) error       { return nil }
func (failingExposureClassifier) RegisterCiliumHostAddr(string) error   { return nil }
func (failingExposureClassifier) UnregisterCiliumHostAddr(string) error { return nil }
func (failingExposureClassifier) GetPodMeta(string) (structs.PodMeta, bool) {
	return structs.PodMeta{}, false
}
func (failingExposureClassifier) IsPodAddr(string) (bool, error)     { return false, nil }
func (failingExposureClassifier) IsHostAddr(string) (bool, error)    { return false, nil }
func (failingExposureClassifier) IsSkippedAddr(string) (bool, error) { return false, nil }
func (failingExposureClassifier) IsNodeAddr(string) (bool, error)    { return false, nil }
func (failingExposureClassifier) IsWorldAddr(string) (bool, error)   { return false, nil }
func (failingExposureClassifier) IsPortExposed(string, uint32) (bool, error) {
	return false, nil
}
func (failingExposureClassifier) IsPortNodePort(string, uint32) (bool, error) {
	return false, nil
}
func (failingExposureClassifier) GetAddrType(string) (modules.AddrType, error) {
	return modules.AddrTypeUnknown, nil
}
