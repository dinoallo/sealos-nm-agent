package mock

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

type DummyExportTrafficService struct {
	log.Logger
	watchedPodIP  string
	watchedHostIP string
}

func NewDummyExportTrafficService(parentLogger log.Logger, watchedPodIP, watchedHostIP string) (*DummyExportTrafficService, error) {
	logger, err := parentLogger.WithCompName("dummy_export_traffic_service")
	if err != nil {
		return nil, err
	}
	return &DummyExportTrafficService{
		Logger:        logger,
		watchedPodIP:  watchedPodIP,
		watchedHostIP: watchedHostIP,
	}, nil
}

func (s *DummyExportTrafficService) SubmitRawPodTrafficEvent(ctx context.Context, e structs.RawTrafficEvent) error {
	if e.RawTrafficEventMeta.SrcIP != s.watchedPodIP && e.RawTrafficEventMeta.DstIP != s.watchedPodIP {
		return nil
	}
	s.Infof("submit pod traffic event: %+v", e)
	return nil
}

func (s *DummyExportTrafficService) SubmitRawHostTrafficEvent(ctx context.Context, e structs.RawTrafficEvent) error {
	if e.RawTrafficEventMeta.SrcIP != s.watchedHostIP && e.RawTrafficEventMeta.DstIP != s.watchedHostIP {
		return nil
	}
	s.Infof("submit host traffic event: %+v", e)
	return nil
}
