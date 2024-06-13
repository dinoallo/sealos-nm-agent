package modules

type BPFPodTrafficModule interface {
	SubscribeToDevice(iface string) error
}

type BPFHostTrafficModule interface {
	SubscribeToDevice(iface string) error
}
