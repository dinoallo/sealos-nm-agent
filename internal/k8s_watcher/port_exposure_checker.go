package k8s_watcher

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/puzpuzpuz/xsync"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

var (
	svcLabelKey = "kubernetes.io/service-name"
)

type PortExposureCheckerParams struct {
	client.Client
	*runtime.Scheme
	modules.Classifier
}

type PortExposureChecker struct {
	services     *xsync.MapOf[string, *SVC]                      // svcHash -> svc
	epSlices     *xsync.MapOf[string, *ES]                       // epSliceHash -> ES
	ingresses    *xsync.MapOf[string, *I]                        // ingressHash -> I
	ibs          *xsync.MapOf[string, *IB]                       // ibHash -> ib
	indexedBySVC *xsync.MapOf[string, *xsync.MapOf[string, *IB]] // svcHash -> ibs
	PortExposureCheckerParams
}

func NewPortExposureChecker(params PortExposureCheckerParams) *PortExposureChecker {
	return &PortExposureChecker{
		services:                  xsync.NewMapOf[*SVC](),
		epSlices:                  xsync.NewMapOf[*ES](),
		ingresses:                 xsync.NewMapOf[*I](),
		ibs:                       xsync.NewMapOf[*IB](),
		indexedBySVC:              xsync.NewMapOf[*xsync.MapOf[string, *IB]](),
		PortExposureCheckerParams: params,
	}
}

func (c *PortExposureChecker) UpdateIngress(newIngress networkingv1.Ingress) error {
	hash := GetIngressHash(newIngress.Name, newIngress.Namespace)
	_, err := c.updateIngress(hash, newIngress)
	return err
}

func (c *PortExposureChecker) UpdateEpSlice(newEpSlice discoveryv1.EndpointSlice) error {
	hash := GetEpSliceHash(newEpSlice.Name, newEpSlice.Namespace)
	_, err := c.updateEpSlice(hash, newEpSlice)
	return err
}

func (c *PortExposureChecker) Dump(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "print ingresses and their backends:\n")
	printI := func(ingressHash string, i *I) bool {
		fmt.Fprintf(w, "ingress: %v\n", ingressHash)
		printRef := func(ibHash string, ib *IB) bool {
			ib.mu.RLock()
			fmt.Fprintf(w, "-> %v's port %v\n", ib.svcHash, ib.sbp)
			ib.mu.RUnlock()
			return true
		}
		i.backends.Range(printRef)
		return true
	}
	c.ingresses.Range(printI)
	fmt.Fprintf(w, "print backends:\n")
	printIB := func(ibHash string, ib *IB) bool {
		fmt.Fprintf(w, "ib: %v\n", ibHash)
		return true
	}
	c.ibs.Range(printIB)
	printSVC := func(svcHash string, svc *SVC) bool {
		fmt.Fprintf(w, "svc %v:\n", svcHash)
		printRef := func(esHash string, es *ES) bool {
			es.mu.RLock()
			fmt.Fprintf(w, "-> %v\n", esHash)
			es.mu.RUnlock()
			return true
		}
		svc.epSlices.Range(printRef)
		return true
	}
	c.services.Range(printSVC)
	printES := func(epSliceHash string, es *ES) bool {
		fmt.Fprintf(w, "epslice: %v\n", epSliceHash)
		return true
	}
	c.epSlices.Range(printES)
}

func (c *PortExposureChecker) updateEpSlice(hash string, latest discoveryv1.EndpointSlice) (*ES, error) {
	// find the owner service of the endpoint slice
	service := c.getOwnerService(latest)
	if service == nil {
		/// if the owner service does not exist, just ignore it
		return nil, nil
	}
	// update the owner service first. this way, its SVC can be correctly initialized
	svcHash := GetServiceHash(service.Name, service.Namespace)
	svc, err := c.updateService(svcHash, *service)
	if err != nil {
		log.Printf("failed to update the service: %v", err)
		return nil, err
	}
	// update the ES of the endpoint slice
	newES := NewES(svc, latest)
	es, loaded := c.epSlices.LoadOrStore(hash, newES)
	if !loaded {
		es = newES
	}
	es.mu.Lock()
	latestEpSlice := NewEndpointSlice(latest)
	es.epSlice = latestEpSlice /// update the pointer to the resource
	es.ownedBy = svc           /// update the pointer to the owner SVC
	es.mu.Unlock()
	svc.epSlices.Store(hash, es)
	// the ES is already updated so it's exposed if there are IBs using its owner SVC as backend
	_updateExposure := func(ibHash string, ib *IB) bool {
		if err := c.updateExposureForIngressBackend(ib, true); err != nil {
			//TODO: handle me
			log.Printf("failed to update exposure to true while removing the epslice")
		}
		return true
	}
	svc.referencedBy.Range(_updateExposure)
	var isNodePort bool = service.Spec.Type == corev1.ServiceTypeNodePort
	for _, servicePort := range service.Spec.Ports {
		if err := c.updateNodePortForEp(servicePort.TargetPort, *es.epSlice, isNodePort); err != nil {
			return nil, err
		}
	}
	return es, nil
}

func (c *PortExposureChecker) removeEpSlice(esHash string) error {
	// load and delete the ES from the lookup table
	es, loaded := c.epSlices.LoadAndDelete(esHash)
	if !loaded {
		// the ES is not found in the lookup table, just ignore it
		return nil
	}
	// remove the reference to itself on its owner SVC
	es.mu.RLock()
	defer es.mu.RUnlock()
	svc := es.ownedBy
	svc.mu.RLock()
	svcHash := GetServiceHash(svc.service.Name, svc.service.Namespace)
	svc.mu.RUnlock()
	// since this endpoint slice is removed, it's not exposed anymore
	_updateExposure := func(ibHash string, ib *IB) bool {
		if err := c.updateExposureForIngressBackend(ib, false); err != nil {
			//TODO: handle me
			log.Printf("failed to update exposure to false while removing the epslice")
		}
		return true
	}
	svc.referencedBy.Range(_updateExposure)
	svc.epSlices.Delete(esHash)
	// garbage collect the owner service if it doesn not have children anymore
	if countEp(svc) <= 0 {
		c.removeService(svcHash)
	}
	return nil
}

func (c *PortExposureChecker) updateService(svcHash string, latest corev1.Service) (*SVC, error) {
	newSVC := NewSVC(latest)
	svc, loaded := c.services.LoadOrStore(svcHash, newSVC)
	if !loaded {
		svc = newSVC
	}
	latestService := NewService(latest)
	svc.mu.Lock()
	svc.service = latestService
	svc.mu.Unlock()
	// set up the reference to itself on existing, matching IB
	ibs, loaded := c.indexedBySVC.Load(svcHash)
	if !loaded || ibs == nil {
		return svc, nil
	}
	updateBackend := func(ibHash string, ib *IB) bool {
		ib.mu.Lock()
		ib.backend = svc
		ib.mu.Unlock()
		svc.referencedBy.Store(ibHash, ib)
		return true
	}
	ibs.Range(updateBackend)
	return svc, nil
}

func (s *PortExposureChecker) removeService(svcHash string) {
	svc, loaded := s.services.LoadAndDelete(svcHash)
	if !loaded {
		return
	}
	deref := func(epHash string, es *ES) bool {
		es.mu.Lock()
		defer es.mu.Unlock()
		es.ownedBy = nil
		return true
	}
	svc.epSlices.Range(deref)
	derefItself := func(ibHash string, ib *IB) bool {
		ib.mu.Lock()
		ib.backend = nil
		ib.mu.Unlock()
		svc.referencedBy.Delete(ibHash)
		return true
	}
	svc.referencedBy.Range(derefItself)
}

func (c *PortExposureChecker) RemoveIngress(hash string) error {
	return c.removeIngress(hash)
}

func (c *PortExposureChecker) RemoveEpSlice(hash string) error {
	return c.removeEpSlice(hash)
}

func (c *PortExposureChecker) updateIngress(hash string, latest networkingv1.Ingress) (*I, error) {
	ns := latest.Namespace
	ingressName := latest.Name
	ingressHash := GetIngressHash(ingressName, ns)
	newI := NewI(latest)
	/// update the I in the lookup table
	i, loaded := c.ingresses.LoadOrStore(hash, newI)
	if !loaded {
		i = newI
	}
	i.mu.Lock()
	latestIngress := NewIngress(latest)
	i.ingress = latestIngress /// update the ingress to the latest version
	i.mu.Unlock()
	backends, err := getBackends(latest) /// get the service backends for the latest ingress
	if err != nil {
		return nil, err
	}
	// dereference all the old ingress backends
	c.derefIngressBackends(ingressHash, i)
	// set up the reference to the new ingress backends
	for _, backend := range backends {
		if backend.Service == nil {
			continue
		}
		svcHash := GetServiceHash(backend.Service.Name, ns)
		ibHash := GetIBHash(svcHash, backend.Service.Port)
		ib, err := c.updateIngressBackend(svcHash, backend.Service.Port)
		if err != nil {
			//TODO: handle me
			log.Printf("unable to update ingress backend %v: %v", ibHash, err)
			continue
		}
		i.backends.Store(ibHash, ib)
		ib.referencedBy.Store(hash, i)
	}
	log.Printf("%v updated", hash)
	return i, nil
}

func (c *PortExposureChecker) removeIngress(hash string) error {
	// delete the I from the lookup table
	i, loaded := c.ingresses.LoadAndDelete(hash)
	if !loaded {
		return nil
	}
	// dereference all ingress backends
	c.derefIngressBackends(hash, i)
	return nil
}

func (c *PortExposureChecker) derefIngressBackends(ingressHash string, i *I) {
	remove := func(ibHash string, ib *IB) bool {
		ib.referencedBy.Delete(ingressHash)
		// garbage collect the the ingress backend if it's not referenced by any ingresses
		if countIngress(ib) <= 0 {
			c.removeIngressBackend(ibHash)
		}
		i.backends.Delete(ibHash)
		return true
	}
	i.backends.Range(remove)
}

func (c *PortExposureChecker) updateIngressBackend(svcHash string, latest networkingv1.ServiceBackendPort) (*IB, error) {
	ibHash := GetIBHash(svcHash, latest)
	newIB := NewIB(svcHash, latest)
	// update the IB in the lookup table
	ib, loaded := c.ibs.LoadOrStore(ibHash, newIB)
	if !loaded {
		ib = newIB
	}
	ib.mu.Lock()
	ib.svcHash = svcHash
	latestSBP := NewServiceBackendPort(latest)
	ib.sbp = latestSBP
	ib.mu.Unlock()
	// update the IB to the table indexed by svcHash for faster lookup
	newIBSet := xsync.NewMapOf[*IB]()
	ibSet, loaded := c.indexedBySVC.LoadOrStore(svcHash, newIBSet)
	if !loaded {
		ibSet = newIBSet
	}
	ibSet.Store(ibHash, ib)
	// set up the backend of this IB
	svc, loaded := c.services.Load(svcHash)
	if !loaded {
		/// this IB currently doesn't have a real backend, ignore the following exposure update
		return ib, nil
	}
	ib.mu.Lock()
	ib.backend = svc
	ib.mu.Unlock()
	svc.referencedBy.Store(ibHash, ib)
	// update exposure
	if err := c.updateExposureForIngressBackend(ib, true); err != nil {
		//TODO: handle me
		log.Printf("failed to update exposure of an ingress backend %v while updating it: %v", ibHash, err)
	}
	return ib, nil
}

func (c *PortExposureChecker) removeIngressBackend(ibHash string) {
	// remove the IB in the lookup table
	ib, loaded := c.ibs.LoadAndDelete(ibHash)
	if !loaded {
		return
	}
	// this ib doesn't have a backend, we don't need to update exposure and handle dereferencing
	if ib.backend == nil {
		return
	}
	if err := c.updateExposureForIngressBackend(ib, false); err != nil {
		//TODO: handle me
		log.Printf("failed to update exposure of an ingress backend %v while removing it: %v", ibHash, err)
	}
	// remove the reference to itself on its backend SVC
	if ib.backend.referencedBy != nil {
		// remove the reference to the backend
		ib.backend.referencedBy.Delete(ibHash)
	}
	// remove the IB from the indexedBySVC lookup table
	ibSet, loaded := c.indexedBySVC.Load(ib.svcHash)
	if !loaded {
		return
	}
	ibSet.Delete(ibHash)
}

func (c *PortExposureChecker) getOwnerService(epSlice discoveryv1.EndpointSlice) *corev1.Service {
	labels := epSlice.GetLabels()
	svcName := labels[svcLabelKey]
	svcNN := types.NamespacedName{
		Name:      svcName,
		Namespace: epSlice.Namespace,
	}
	var service corev1.Service
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := c.Get(ctx, svcNN, &service); err != nil {
		return nil
	}
	return &service
}

func (c *PortExposureChecker) updateExposureForIngressBackend(ib *IB, exposure bool) error {
	svc := ib.backend
	if svc == nil {
		return nil
	}
	targetPort := getForwardingPort(svc, *ib.sbp)
	_updateExposure := func(esHash string, es *ES) bool {
		if err := c.updateExposureForEp(targetPort, *es.epSlice, exposure); err != nil {
			//TODO: handle me
			return true
		}
		return true
	}
	svc.epSlices.Range(_updateExposure)
	return nil
}

func (c *PortExposureChecker) updateNodePortForEp(targetPort intstr.IntOrString, epSlice EndpointSlice, isNodePort bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	for _, ep := range epSlice.Endpoints {
		if ep.TargetRef == nil {
			continue
		}
		podHash := GetPodHash(ep.TargetRef.Name, ep.TargetRef.Namespace)
		if portNumber := targetPort.IntVal; portNumber != 0 {
			c._updateNodePortForEp(podHash, ep.Addresses, portNumber, isNodePort)
		} else if portName := targetPort.StrVal; portName != "" {
			var pod corev1.Pod
			podNN := types.NamespacedName{
				Name:      ep.TargetRef.Name,
				Namespace: ep.TargetRef.Namespace,
			}
			if err := c.Get(ctx, podNN, &pod); err != nil {
				//TODO: handle me
				continue
			}
			portNumber, exists := getNamedPort(pod, targetPort.StrVal)
			if exists {
				c._updateNodePortForEp(podHash, ep.Addresses, portNumber, isNodePort)
			}
		}
	}
	return nil
}

func (c *PortExposureChecker) updateExposureForEp(targetPort intstr.IntOrString, epSlice EndpointSlice, exposure bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	for _, ep := range epSlice.Endpoints {
		if ep.TargetRef == nil {
			continue
		}
		podHash := GetPodHash(ep.TargetRef.Name, ep.TargetRef.Namespace)
		// since the upstream IB specify a port number, mark the port with the port number as exposed
		if portNumber := targetPort.IntVal; portNumber != 0 {
			c._updateExposureForEp(podHash, ep.Addresses, portNumber, exposure)
		} else if portName := targetPort.StrVal; portName != "" {
			// the upstream IB doesn't specify a port number. Instead, it provides a port name.
			// in this case, check if any ports of this pod(the owner of this endpoint) have
			// the same name and get the port number
			var pod corev1.Pod
			podNN := types.NamespacedName{
				Name:      ep.TargetRef.Name,
				Namespace: ep.TargetRef.Namespace,
			}
			if err := c.Get(ctx, podNN, &pod); err != nil {
				//TODO: handle me
				continue
			}
			portNumber, exists := getNamedPort(pod, targetPort.StrVal)
			if exists {
				c._updateExposureForEp(podHash, ep.Addresses, portNumber, exposure)
			}
		}
	}
	return nil
}

func (c *PortExposureChecker) _updateExposureForEp(podHash string, addrs []string, portNumber int32, exposure bool) {
	for _, addr := range addrs {
		if exposure {
			if err := c.makeExposed(addr, portNumber); err != nil {
				log.Printf("failed to make port %v exposed for pod %v@%v", portNumber, podHash, addr)
				continue
			}
		} else {
			if err := c.makePrivate(addr, portNumber); err != nil {
				log.Printf("failed to make port %v private for pod %v@%v", portNumber, podHash, addr)
				continue
			}
		}
	}
}

func (c *PortExposureChecker) _updateNodePortForEp(podHash string, addrs []string, portNumber int32, isNodePort bool) {
	for _, addr := range addrs {
		if isNodePort {
			if err := c.makeNodePort(addr, portNumber); err != nil {
				log.Printf("failed to make port %v a node port for pod %v@%v", portNumber, podHash, addr)
				continue
			}
		} else {
			if err := c.makeNonNodePort(addr, portNumber); err != nil {
				log.Printf("failed to make port %v a non node port for pod %v@%v", portNumber, podHash, addr)
				continue
			}
		}
	}
}

func (c *PortExposureChecker) makeExposed(podAddr string, podPort int32) error {
	// make the port exposed
	if err := c.RegisterExposedPort(podAddr, uint32(podPort)); err != nil {
		return err
	}
	return nil
}

func (c *PortExposureChecker) makePrivate(podAddr string, podPort int32) error {
	if err := c.UnregisterExposedPort(podAddr, uint32(podPort)); err != nil {
		return err
	}
	return nil
}

func (c *PortExposureChecker) makeNodePort(podAddr string, podPort int32) error {
	// make the port a node port
	if err := c.RegisterNodePort(podAddr, uint32(podPort)); err != nil {
		return err
	}
	return nil
}

func (c *PortExposureChecker) makeNonNodePort(podAddr string, podPort int32) error {
	if err := c.UnregisterNodePort(podAddr, uint32(podPort)); err != nil {
		return err
	}
	return nil
}

type IB struct {
	svcHash      string
	sbp          *ServiceBackendPort
	backend      *SVC
	referencedBy *xsync.MapOf[string, *I] // ingressHash -> i

	mu *sync.RWMutex
}

func NewIB(svcHash string, _sbp networkingv1.ServiceBackendPort) *IB {
	sbp := NewServiceBackendPort(_sbp)
	return &IB{
		svcHash:      svcHash,
		sbp:          sbp,
		referencedBy: xsync.NewMapOf[*I](),
		mu:           &sync.RWMutex{},
	}
}

// I represents of a k8s networkingv1.Ingress resource
type I struct {
	ingress  *Ingress
	backends *xsync.MapOf[string, *IB] // ibhash -> ib

	mu *sync.RWMutex
}

func NewI(_ingress networkingv1.Ingress) *I {
	ingress := NewIngress(_ingress)
	return &I{
		ingress:  ingress,
		backends: xsync.NewMapOf[*IB](),
		mu:       &sync.RWMutex{},
	}
}

// SVC represents a k8s corev1.Service resource
type SVC struct {
	service      *Service
	epSlices     *xsync.MapOf[string, *ES] // esHash -> epSlice
	referencedBy *xsync.MapOf[string, *IB] // ibHash -> ib

	mu *sync.RWMutex
}

func NewSVC(_svc corev1.Service) *SVC {
	svc := NewService(_svc)
	return &SVC{
		service:      svc,
		epSlices:     xsync.NewMapOf[*ES](),
		referencedBy: xsync.NewMapOf[*IB](),
		mu:           &sync.RWMutex{},
	}
}

// ES represents a k8s discoveryv1.EndpointSlice resource
type ES struct {
	epSlice *EndpointSlice
	ownedBy *SVC

	mu *sync.RWMutex
}

func NewES(ownedBy *SVC, _epSlice discoveryv1.EndpointSlice) *ES {
	epSlice := NewEndpointSlice(_epSlice)
	return &ES{
		epSlice: epSlice,
		ownedBy: ownedBy,
		mu:      &sync.RWMutex{},
	}
}

func getForwardingPort(_svc *SVC, sbp ServiceBackendPort) intstr.IntOrString {
	_svc.mu.RLock()
	defer _svc.mu.RUnlock()
	svc := _svc.service
	var targetPort intstr.IntOrString
	if svc == nil {
		return targetPort
	}
	if sbp.Number != 0 {
		targetPort = getForwardingPortByNumber(*svc, sbp.Number)
	} else if sbp.Name != "" {
		targetPort = getForwardingPortByName(*svc, sbp.Name)
	}
	return targetPort
}

func countIngress(ib *IB) int {
	var c int = 0
	if ib.referencedBy == nil {
		return c
	}
	count := func(ingressHash string, i *I) bool {
		c++
		return true
	}
	ib.referencedBy.Range(count)
	return c
}

func countEp(svc *SVC) int {
	var c int = 0
	if svc.epSlices == nil {
		return c
	}
	count := func(esHash string, es *ES) bool {
		c++
		return true
	}
	svc.epSlices.Range(count)
	return c
}
