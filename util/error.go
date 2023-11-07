package util

import (
	"errors"
)

var (
	ErrBPFProgramNotLoaded      = errors.New("the bpf program was not loaded")
	ErrBPFProgramNotPinned      = errors.New("the bpf program was not pinned")
	ErrBPFMapFailedToCheck      = errors.New("failed to check if the bpf map exists")
	ErrBPFMapNotExist           = errors.New("the bpf map does not exist")
	ErrBPFMapAlreadyExists      = errors.New("the bpf map already exists")
	ErrBPFMapNotLoaded          = errors.New("the bpf map was not loaded")
	ErrBPFMapNotPinned          = errors.New("the bpf map was not pinned")
	ErrBPFMapNotUpdated         = errors.New("the bpf map was not updated")
	ErrBPFMapNotInitialized     = errors.New("the bpf map was not initialized")
	ErrBPFMapNotRemoved         = errors.New("the bpf map was not removed")
	ErrBPFCustomCallMapNotExist = errors.New("the bpf map for custom call does not exist")

	ErrUnknownDirection = errors.New("this direction type is not known")
)
