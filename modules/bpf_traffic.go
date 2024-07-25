package modules

import "errors"

type BPFTrafficFactory interface {
	SubscribeToCep(eid int64) error
	UnsubscribeFromCep(eid int64) error
	SubscribeToHostDev(iface string) error
	UnsubscribeFromHostDev(iface string) error
}

var (
	ErrDeviceNotFound              = errors.New("this device cannot be found")
	ErrCepNotFound                 = errors.New("this cilium endpoint cannot be found")
	ErrClsactQdiscNotFound         = errors.New("failed to find the clsact qdisc of this device")
	ErrAddingEgressFilter          = errors.New("failed to add filter at the egress side")
	ErrAddingIngressFilter         = errors.New("failed to add filter at the ingress side")
	ErrDeletingEgressFilter        = errors.New("failed to delete filter at the egress side")
	ErrDeletingIngressFilter       = errors.New("failed to delete filter at the ingress side")
	ErrClosingDeviceHooker         = errors.New("failed to close the device hooker")
	ErrCreatingDeviceHooker        = errors.New("failed to create a device hooker")
	ErrInitializingDeviceHooker    = errors.New("failed to initialize a device hooker")
	ErrCreatingTrafficEventHandler = errors.New("failed to create the reader for traffic events")
	ErrCreatingTrafficEventReader  = errors.New("failed to create the handler for traffic events")
	ErrLoadingBPFObjects           = errors.New("failed to load bpf objects")
	ErrLoadingLxcTrafficObjs       = errors.New("failed to load pod traffic bpf objects")
	ErrLoadingHostTrafficObjs      = errors.New("failed to load host traffic bpf objects")
	ErrLoadingCepTrafficObjs       = errors.New("failed to load cep traffic bpf objects")
	ErrAttachingEgressHookToCCM    = errors.New("failed to attach egress hook to cilium custom call map")
	ErrDetachingAllHooksFromCCM    = errors.New("failed to detach all hooks from cilium custom call map")

	ErrGettingHostEndian    = errors.New("failed to get the endian of the host")
	ErrReadingFromRawSample = errors.New("failed to read from a raw sample")

	ErrCreatingEgressPodTrafficReader  = errors.New("failed to create traffic reader for pod egress traffic")
	ErrCreatingEgressPodNotiReader     = errors.New("failed to create traffic reader for pod egress traffic notification")
	ErrCreatingEgressHostTrafficReader = errors.New("failed to create traffic reader for host egress traffic")
	ErrCreatingEgressHostNotiReader    = errors.New("failed to create traffic reader for host egress traffic notifications")
	ErrReadingFromRingBuf              = errors.New("failed to read from the ring buffer")
)
