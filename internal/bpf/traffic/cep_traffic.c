// clang-format off
//go:build ignore
#include "../headers/common.h"
// clang-format on

char __license[] SEC("license") = "Dual MIT/GPL";

const struct event_t *unused_cep_traffic_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} egress_cep_traffic_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} ingress_cep_traffic_events SEC(".maps");

static __always_inline void marshal(struct event_t *event,
                                    const struct bpf_sock *sk) {
  if (!sk) {
    return;
  }
  event->protocol = sk->protocol;
  event->family = sk->family;
  event->src_ip4 = sk->src_ip4;
  event->dst_ip4 = sk->dst_ip4;
  // TODO: how to use #pragma unroll to imple this and pass the verifier? (clang
  // seems to not unroll this)
  // We need to be careful about loops since the verifier is usually not gonna
  // be happy with them... So we manually unroll them.
  event->src_ip6[0] = sk->src_ip6[0];
  event->src_ip6[1] = sk->src_ip6[1];
  event->src_ip6[2] = sk->src_ip6[2];
  event->src_ip6[3] = sk->src_ip6[3];
  event->dst_ip6[0] = sk->dst_ip6[0];
  event->dst_ip6[1] = sk->dst_ip6[1];
  event->dst_ip6[2] = sk->dst_ip6[2];
  event->dst_ip6[3] = sk->dst_ip6[3];
  event->src_port = sk->src_port;
  event->dst_port = sk->dst_port;
}

static __always_inline void submit_egress_traffic(struct __sk_buff *ctx,
                                                  u32 identity) {
  struct event_t event = {};
  event.len = ctx->len;
  event.identity = identity;
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    return;
  }
  sk = bpf_sk_fullsock(sk);
  marshal(&event, sk);
  bpf_perf_event_output(ctx, &egress_cep_traffic_events, BPF_F_CURRENT_CPU,
                        &event, sizeof(struct event_t));
}
static __always_inline void submit_ingress_traffic(struct __sk_buff *ctx,
                                                   u32 identity) {
  struct event_t event = {};
  event.len = ctx->len;
  event.identity = identity;
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    return;
  }
  sk = bpf_sk_fullsock(sk);
  marshal(&event, sk);
  bpf_perf_event_output(ctx, &ingress_cep_traffic_events, BPF_F_CURRENT_CPU,
                        &event, sizeof(struct event_t));
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
