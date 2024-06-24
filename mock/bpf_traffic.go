package mock

import "log"

// this implementation is only used for testing
type DummyBPFTrafficModule struct {
}

func NewDummyBPFTrafficModule() *DummyBPFTrafficModule {
	return &DummyBPFTrafficModule{}
}

func (m *DummyBPFTrafficModule) SubscribeToPodDevice(ifaceName string) error {
	log.Printf("subscribe to pod device: %v", ifaceName)
	return nil
}

func (m *DummyBPFTrafficModule) SubscribeToHostDevice(ifaceName string) error {
	log.Printf("subscribe to host device: %v", ifaceName)
	return nil
}

func (m *DummyBPFTrafficModule) UnsubscribeFromPodDevice(ifaceName string) error {
	log.Printf("unsubscribe to pod device: %v", ifaceName)
	return nil
}

func (m *DummyBPFTrafficModule) UnsubscribeFromHostDevice(ifaceName string) error {
	log.Printf("unsubscribe to host device: %v", ifaceName)
	return nil
}
