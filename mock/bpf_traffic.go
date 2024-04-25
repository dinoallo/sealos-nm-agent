package mock

// this implementation is only used for testing
type DummyBPFTrafficModule struct {
}

func NewDummyBPFTrafficModule() *DummyBPFTrafficModule {
	return &DummyBPFTrafficModule{}
}

func (m *DummyBPFTrafficModule) SubscribeToDevice(iface string) error {
	return nil
}
