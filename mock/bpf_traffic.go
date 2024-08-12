package mock

import "log"

// this implementation is only used for testing
type DummyBPFTrafficModule struct {
}

func NewDummyBPFTrafficModule() *DummyBPFTrafficModule {
	return &DummyBPFTrafficModule{}
}

func (m *DummyBPFTrafficModule) GetEgressFilterFDForHostDev() int {
	log.Printf("getting the egress filter fd for host dev")
	return 0
}

func (m *DummyBPFTrafficModule) GetEgressFilterFDForPodDev() int {
	log.Printf("getting the egress filter fd for pod dev")
	return 0
}
