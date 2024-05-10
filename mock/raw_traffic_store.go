package mock

import (
	"context"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/common/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
)

type DummyRawTrafficStoreParams struct {
	log.Logger
}

type DummyRawTrafficStore struct {
	DummyRawTrafficStoreParams
}

func NewDummyRawTrafficStore(params DummyRawTrafficStoreParams) *DummyRawTrafficStore {
	return &DummyRawTrafficStore{
		DummyRawTrafficStoreParams: params,
	}
}

func (s *DummyRawTrafficStore) AcceptRawTrafficEvent(ctx context.Context, event structs.RawTrafficEvent) error {
	s.Infof("src: %v:%v => dst: %v:%v; data_bytes: %v", event.RawTrafficEventMeta.SrcIP, event.RawTrafficEventMeta.SrcPort, event.RawTrafficEventMeta.DstIP, event.RawTrafficEventMeta.DstPort, event.DataBytes)
	return nil
}
