// clang-format off
//go:build ignore
#include "../headers/common.h"
// clang-format on

char __license[] SEC("license") = "Dual MIT/GPL";

const struct event_t *unused_traffic_event __attribute__((unused));
const struct notification_t *unused_notification __attribute__((unused));

#define TC_ACT_UNSPEC -1

// this is 128MB
#define TRAFFIC_EVENTS_MAX_ENTRIES 134217728
// this is 4KB
#define NOTIFICATIONS_MAX_ENTRIES 4096

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, TRAFFIC_EVENTS_MAX_ENTRIES);
} egress_cep_traffic_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NOTIFICATIONS_MAX_ENTRIES);
} submit_cep_traffic_notifications SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, TRAFFIC_EVENTS_MAX_ENTRIES);
} egress_host_traffic_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NOTIFICATIONS_MAX_ENTRIES);
} submit_host_traffic_notifications SEC(".maps");

static __always_inline void submit_egress_traffic(struct __sk_buff *ctx,
                                                  u32 identity, void *events,
                                                  void *notifications) {

  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    return;
  }
  sk = bpf_sk_fullsock(sk);
  if (!sk) {
    return;
  }

  struct event_t *e = bpf_ringbuf_reserve(events, sizeof(struct event_t), 0);
  if (!e) {
    struct notification_t *notif =
        bpf_ringbuf_reserve(notifications, sizeof(struct notification_t), 0);
    if (!notif) {
      return;
    }
    notif->error = ERR_BUF_FULL;
    bpf_ringbuf_submit(notif, 0);
    return;
  }
  // From now on, if we need to return early before `bpf_ringbuf_submit`, we
  // need to explicitly call `bpf_ringbuf_discard`
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

  submit_egress_traffic(ctx, identity, &egress_cep_traffic_events,
                        &submit_cep_traffic_notifications);

  return ret;
}

SEC("classifier")
int egress_host_traffic_hook(struct __sk_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;

  submit_egress_traffic(ctx, identity, &egress_host_traffic_events,
                        &submit_host_traffic_notifications);

  return TC_ACT_UNSPEC;
}
