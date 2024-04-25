package network_device

import "errors"

var (
	ErrConvertKeyToIfaceIDFailed = errors.New("failed to convert to interface id")
	ErrUpdateDevices             = errors.New("failed to update devices")
)
