package common

import "errors"

var (
	ErrUnknownTrafficDirection = errors.New("the traffic direction is not known")
	ErrUnknownTCDirection      = errors.New("the tc direction is not known")
)
