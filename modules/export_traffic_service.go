package modules

import (
	"context"
	"errors"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
)

var (
	ErrTimeoutSubmittingRTE = errors.New("timeout submitting raw traffic event")
)

type ExportTrafficService interface {
	SubmitRawTrafficEvent(ctx context.Context, e structs.RawTrafficEvent) error
}
