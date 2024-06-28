// clang-format off
//go:build ignore

#include "../headers/common.h"

// clang-format on
// #define TC_ACT_OK 0
#define TC_ACT_UNSPEC -1
char __license[] SEC("license") = "Dual MIT/GPL";

const struct event_t *unused_lxc_traffic_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} egress_lxc_traffic_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} ingress_lxc_traffic_events SEC(".maps");

static __always_inline void submit_egress_traffic(struct __sk_buff *ctx) {
  struct event_t event = {};
  event.len = ctx->len;
  event.protocol = ctx->protocol;
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    return;
  }
  sk = bpf_sk_fullsock(sk);
  marshal(&event, sk);
  bpf_perf_event_output(ctx, &egress_lxc_traffic_events, BPF_F_CURRENT_CPU,
                        &event, sizeof(struct event_t));
}
static __always_inline void submit_ingress_traffic(struct __sk_buff *ctx) {
  struct event_t event = {};
  event.len = ctx->len;
  event.protocol = ctx->protocol;
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    return;
  }
  sk = bpf_sk_fullsock(sk);
  marshal(&event, sk);
  bpf_perf_event_output(ctx, &ingress_lxc_traffic_events, BPF_F_CURRENT_CPU,
                        &event, sizeof(struct event_t));
}

SEC("classifier")
int egress_lxc_traffic_hook(struct __sk_buff *ctx) {
  submit_egress_traffic(ctx);
  return TC_ACT_UNSPEC;
}

SEC("classifier")
int ingress_lxc_traffic_hook(struct __sk_buff *ctx) {
  submit_ingress_traffic(ctx);
  return TC_ACT_UNSPEC;
}
