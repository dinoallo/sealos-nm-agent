// clang-format off
//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/bpf_helpers.h"

// clang-format on
// #define TC_ACT_OK 0
#define TC_ACT_UNSPEC -1
char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
  __u32 len;
  __u32 family;
  __u32 protocol;
  __u32 dst_ip4;
  __u32 src_ip4;
  __u32 dst_ip6[4];
  __u32 src_ip6[4];
  __u32 src_port;
  __be16 dst_port;
};

const struct event_t *unused_traffic_event __attribute__((unused));

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

static __always_inline void marshal(struct event_t *event,
                                    const struct bpf_sock *sk) {
  if (!sk) {
    return;
  }
  event->protocol = sk->protocol;
  event->family = sk->family;
  event->src_ip4 = sk->src_ip4;
  event->dst_ip4 = sk->dst_ip4;
  int i;
  for (i = 0; i < 4; i++) {
    event->src_ip6[i] = sk->src_ip6[i];
    event->dst_ip6[i] = sk->dst_ip6[i];
  }
  event->src_port = sk->src_port;
  event->dst_port = sk->dst_port;
}

static __always_inline void submit_egress_traffic(struct __sk_buff *ctx) {
  struct event_t event = {};
  event.len = ctx->len;
  struct bpf_sock *sk = ctx->sk;
  if (sk) {
    sk = bpf_sk_fullsock(sk);
    marshal(&event, sk);
  }
  bpf_perf_event_output(ctx, &egress_traffic_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(struct event_t));
}
static __always_inline void submit_ingress_traffic(struct __sk_buff *ctx) {
  struct event_t event = {};
  event.len = ctx->len;
  struct bpf_sock *sk = ctx->sk;
  if (sk) {
    sk = bpf_sk_fullsock(sk);
    marshal(&event, sk);
  }
  bpf_perf_event_output(ctx, &ingress_traffic_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(struct event_t));
}

SEC("classifier")
int egress_traffic_hook(struct __sk_buff *ctx) {
  submit_egress_traffic(ctx);
  return TC_ACT_UNSPEC;
}

SEC("classifier")
int ingress_traffic_hook(struct __sk_buff *ctx) {
  submit_ingress_traffic(ctx);
  return TC_ACT_UNSPEC;
}
