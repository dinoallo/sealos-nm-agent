package modules

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
)

type RawTrafficStore interface {
	AcceptRawTrafficEvent(ctx context.Context, event structs.RawTrafficEvent) error
}
