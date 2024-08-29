package modules

import "errors"

type BPFTrafficFactory interface {
	InitPod(netNs string) error
	InitHostIface(ifName string) error
}

var (
	ErrDeviceNotFound              = errors.New("this device cannot be found")
	ErrCepNotFound                 = errors.New("this cilium endpoint cannot be found")
	ErrClsactQdiscNotFound         = errors.New("failed to find the clsact qdisc of this device")
	ErrClsactQdiscAlreadyExists    = errors.New("the clsact qdisc of this device of this already exists.")
	ErrAddingEgressFilter          = errors.New("failed to add filter at the egress side")
	ErrAddingIngressFilter         = errors.New("failed to add filter at the ingress side")
	ErrDeletingEgressFilter        = errors.New("failed to delete filter at the egress side")
	ErrDeletingIngressFilter       = errors.New("failed to delete filter at the ingress side")
	ErrClosingDeviceHooker         = errors.New("failed to close the device hooker")
	ErrCreatingDeviceHooker        = errors.New("failed to create a device hooker")
	ErrInitializingDeviceHooker    = errors.New("failed to initialize a device hooker")
	ErrCreatingTrafficEventHandler = errors.New("failed to create the reader for traffic events")
	ErrCreatingTrafficEventReader  = errors.New("failed to create the handler for traffic events")
	ErrCreatingTrafficHooker       = errors.New("failed to create the hooker for manipulating traffic programs and maps")
	ErrLoadingBPFObjects           = errors.New("failed to load bpf objects")
	ErrLoadingTrafficObjs          = errors.New("failed to load bpf traffic objects")
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
