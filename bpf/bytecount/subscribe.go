package bytecount

import "context"

func (bf *Factory) Subscribe(ctx context.Context, addr string, port uint32) error {
	return bf.store.AddSubscribedPort(ctx, addr, port)
}

func (bf *Factory) Unsubscribe(ctx context.Context, addr string, port uint32) error {
	return bf.store.RemoveSubscribedPort(ctx, addr, port)
}
