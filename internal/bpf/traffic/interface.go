package traffic

type BPFTrafficModule interface {
	SubscribeToDevice(iface string) error
}
