// clang-format off
//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_core_read.h"
#include "../headers/bpf_tracing.h"

// clang-format on
char __license[] SEC("license") = "Dual MIT/GPL";

struct traffic_event_t {
  __u32 len;
  __u32 family;
  __u32 protocol;
  __u32 dst_ip4;
  __u32 src_ip4;
  // __u32 dst_ip6[4];
  // __u32 src_ip6[4];
  __u32 src_port;
  __be16 dst_port;
  __u32 identity;
};

const struct traffic_event_t *unused_traffic_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} egress_traffic_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} ingress_traffic_events SEC(".maps");

static __always_inline void marshal(struct traffic_event_t *event,
                                    const struct bpf_sock *sk) {
  if (!sk) {
    return;
  }
  event->protocol = sk->protocol;
  event->family = sk->family;
  event->src_ip4 = sk->src_ip4;
  event->dst_ip4 = sk->dst_ip4;
  event->src_port = sk->src_port;
  event->dst_port = sk->dst_port;
}

static __always_inline void egress_update_bytecount(struct __sk_buff *ctx,
                                                    u32 identity) {
  struct traffic_event_t event = {};
  event.len = ctx->len;
  event.identity = identity;
  struct bpf_sock *sk = ctx->sk;
  if (sk) {
    sk = bpf_sk_fullsock(sk);
    marshal(&event, sk);
  }
  bpf_perf_event_output(ctx, &egress_traffic_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(struct traffic_event_t));
}
static __always_inline void ingress_update_bytecount(struct __sk_buff *ctx,
                                                     u32 identity) {
  struct traffic_event_t event = {};
  event.len = ctx->len;
  event.identity = identity;
  struct bpf_sock *sk = ctx->sk;
  if (sk) {
    sk = bpf_sk_fullsock(sk);
    marshal(&event, sk);
  }
  bpf_perf_event_output(ctx, &ingress_traffic_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(struct traffic_event_t));
}
SEC("classifier")
int egress_bytecount_custom_hook(struct __sk_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;
  int ret = (custom_meta >> 24) & 0xff;

  egress_update_bytecount(ctx, identity);

  return ret;
}

SEC("classifier")
int ingress_bytecount_custom_hook(struct __sk_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;
  int ret = (custom_meta >> 24) & 0xff;

  ingress_update_bytecount(ctx, identity);

  return ret;
}
