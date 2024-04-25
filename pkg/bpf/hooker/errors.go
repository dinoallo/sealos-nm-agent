package hooker

import "errors"

var (
	ErrCiliumCCMNotExists  = errors.New("the cilium custom call map doesn't exist")
	ErrStatingCiliumCCM    = errors.New("failed to stat the cilium custom call map")
	ErrLoadingCiliumCCM    = errors.New("failed to load the cilium custom call map")
	ErrGettingCiliumCCMKey = errors.New("failed to get the cilium custom call map key")
	ErrUpdatingCiliumCCM   = errors.New("failed to update the cilium custom call map")

	ErrGettingInterfaceName = errors.New("failed to get the interface by name")
	ErrEstablishingSocket   = errors.New("failed to establish a RTNETLINK socket for traffic control")
	ErrSettingExtAck        = errors.New("failed to set the extend ack option")
	ErrClosingSocket        = errors.New("failed to close the RTNETLINK socket")
	// ErrGettingHandle        = errors.New("failed to get the handle ") //TODO: FIX ME
	ErrGettingParentHandle = errors.New("failed ") //TODO: FIX ME
	// ErrAddingQdisc          = errors.New("failed to add a qdisc")
	// ErrDeletingQdisc        = errors.New("failed to delete a qdisc")
	// ErrUpdatingQdisc        = errors.New("failed to update a qdisc for an interface")
	ErrSettingUpQdisc = errors.New("failed to set up the clsact qdisc for this interface")
	// ErrOldQdiscInvalid    = errors.New("the old qdisc is not valid???")
	ErrQdiscInvalid   = errors.New("the qdisc is not valid???")
	ErrAddingFilter   = errors.New("failed to add a filter")
	ErrDeletingFilter = errors.New("failed to delete a filter")
	// ErrUpdatingFilter     = errors.New("failed to update a filter for an interface")
	// ErrOldFilterInvalid   = errors.New("the old filter is not valid???")
	ErrFilterInvalid      = errors.New("the filter is not valid???")
	ErrGettingFD          = errors.New("failed to get the file descriptor of the program hook")
	ErrProgramHookInvalid = errors.New("a valid program hook is required")
)
