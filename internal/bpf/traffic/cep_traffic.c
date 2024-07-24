// clang-format off
//go:build ignore
#include "../headers/common.h"
// clang-format on

char __license[] SEC("license") = "Dual MIT/GPL";

const struct event_t *unused_cep_traffic_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 131072 * 1024); // 128M
} egress_cep_traffic_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 131072 * 1024); // 128M
} ingress_cep_traffic_events SEC(".maps");

static __always_inline void submit_egress_traffic(struct __sk_buff *ctx,
                                                  u32 identity) {

  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    return;
  }
  sk = bpf_sk_fullsock(sk);
  if (!sk) {
    return;
  }

  struct event_t *e = bpf_ringbuf_reserve(&egress_cep_traffic_events,
                                          sizeof(struct event_t), 0);
  if (!e)
    return;
  // From now on, if we need to return early before `bpf_ringbuf_submit`, we
  // need to explicitly call `bpf_ringbuf_discard`
  e->len = ctx->len;
  e->identity = identity;
  e->protocol = ctx->protocol;

  marshal(e, sk);

  bpf_ringbuf_submit(e, 0);
  return;
}
static __always_inline void submit_ingress_traffic(struct __sk_buff *ctx,
                                                   u32 identity) {
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    return;
  }
  sk = bpf_sk_fullsock(sk);
  if (!sk) {
    return;
  }

  struct event_t *e = bpf_ringbuf_reserve(&ingress_cep_traffic_events,
                                          sizeof(struct event_t), 0);
  if (!e)
    return;
  e->len = ctx->len;
  e->identity = identity;
  e->protocol = ctx->protocol;

  marshal(e, sk);

  bpf_ringbuf_submit(e, 0);
  return;
}

SEC("classifier")
int egress_cep_traffic_hook(struct __sk_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;
  int ret = (custom_meta >> 24) & 0xff;

  submit_egress_traffic(ctx, identity);

  return ret;
}

SEC("classifier")
int ingress_cep_traffic_hook(struct __sk_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;
  int ret = (custom_meta >> 24) & 0xff;

  submit_ingress_traffic(ctx, identity);

  return ret;
}
