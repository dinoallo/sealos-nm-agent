package debug

import (
	"net/http"
	"net/http/pprof"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
)

type DebugServiceParams struct {
	ParentLogger log.Logger
	conf.DebugServiceConfig
}

type DebugService struct {
	log.Logger
	DebugServiceParams
}

func NewDebugService(params DebugServiceParams) (*DebugService, error) {
	logger, err := params.ParentLogger.WithCompName("debug_service")
	if err != nil {
		return nil, err
	}
	return &DebugService{
		Logger:             logger,
		DebugServiceParams: params,
	}, nil
}

func (s *DebugService) Start() error {
	if !s.Enabled {
		return nil
	}
	mux := http.NewServeMux()
	if s.Pprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	}

	go func() {
		err := http.ListenAndServe(s.Addr, mux)
		if err != nil {
			s.Errorf("failed to listen and serve: %v", err)
		}
	}()
	return nil
}
