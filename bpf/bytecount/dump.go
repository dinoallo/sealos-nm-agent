package bytecount

import "context"

func (bf *Factory) DumpTraffic(ctx context.Context, addr string, tag string, reset bool) (uint64, uint64, error) {
	if p, err := bf.store.DumpTraffic(ctx, addr, tag, reset); err != nil {
		return 0, 0, err
	} else {
		return p.SentBytes, p.RecvBytes, nil
	}
}
