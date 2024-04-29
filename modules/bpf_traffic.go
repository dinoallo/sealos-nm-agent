package modules

type BPFTrafficModule interface {
	SubscribeToDevice(iface string) error
}
