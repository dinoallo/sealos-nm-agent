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
	s.Infof("src_ip: %v => dst_ip: %v; data_bytes: %v", event.RawTrafficEventMeta.SrcIP, event.RawTrafficEventMeta.DstIP, event.DataBytes)
	return nil
}
