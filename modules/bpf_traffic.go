package modules

import "errors"

type BPFTrafficFactoryConfig struct {
	ReaderMaxWorker  int `env:"READER_MAX_WORKER"`
	HandlerMaxWorker int `env:"HANDLER_MAX_WORKER"`
}

type BPFTrafficFactory interface {
	SubscribeToPodDevice(ifaceName string) error
	SubscribeToHostDevice(ifaceName string) error
	UnsubscribeFromPodDevice(ifaceName string) error
	UnsubscribeFromHostDevice(ifaceName string) error
}

var (
	ErrDeviceNotFound                    = errors.New("this device cannot be found")
	ErrAddingEgressFilter                = errors.New("failed to add filter at the egress side")
	ErrAddingIngressFilter               = errors.New("failed to add filter at the ingress side")
	ErrDeletingEgressFilter              = errors.New("failed to delete filter at the egress side")
	ErrDeletingIngressFilter             = errors.New("failed to delete filter at the ingress side")
	ErrClosingDeviceHooker               = errors.New("failed to close the device hooker")
	ErrCreatingDeviceHooker              = errors.New("failed to create a device hooker")
	ErrInitializingDeviceHooker          = errors.New("failed to initialize a device hooker")
	ErrCreatingLogger                    = errors.New("failed to create a logger")
	ErrCreatingTrafficEventHandler       = errors.New("failed to create the reader for traffic events")
	ErrCreatingTrafficEventReader        = errors.New("failed to create the handler for traffic events")
	ErrLoadingBPFObjects                 = errors.New("failed to load bpf objects")
	ErrLoadingPodTrafficObjs             = errors.New("failed to load pod traffic bpf objects")
	ErrLoadingHostTrafficObjs            = errors.New("failed to load host traffic bpf objects")
	ErrCreatingHostEgressPerfEventReader = errors.New("failed to create a event reader for egress perf events")
	ErrCreatingPodIngressPerfEventReader = errors.New("failed to create a event reader for ingress pod events")
)
