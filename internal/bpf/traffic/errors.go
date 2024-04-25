package traffic

import "errors"

var (
	ErrAddingEgressFilter   = errors.New("failed to add filter at the egress side")
	ErrClosingDeviceHooker  = errors.New("failed to close the device hooker")
	ErrCreatingDeviceHooker = errors.New("failed to create a device hooker")
	ErrCreatingLogger       = errors.New("failed to create a logger")
	ErrCreatingEventHandler = errors.New("failed to create a reader for egress traffic event")
	ErrCreatingEventReader  = errors.New("failed to create a handler for egress traffic event")
	ErrLoadingBPFObjects    = errors.New("failed to load bpf objects")
)
