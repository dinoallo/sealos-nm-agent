package mock

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

type DummyExportTrafficService struct {
	log.Logger
}

func NewDummyExportTrafficService(parentLogger log.Logger) (*DummyExportTrafficService, error) {
	logger, err := parentLogger.WithCompName("dummy_export_traffic_service")
	if err != nil {
		return nil, err
	}
	return &DummyExportTrafficService{
		Logger: logger,
	}, nil
}

func (s *DummyExportTrafficService) SubmitRawTrafficEvent(ctx context.Context, e structs.RawTrafficEvent) error {
	s.Infof("submit: %+v", e)
	return nil
}
