// clang-format off
//go:build ignore
#ifndef _COMMON_H__
#define _COMMON_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

// clang-format on

struct event_t {
  __u32 protocol;
  __u32 len;
  __u32 family;
  __u32 sk_protocol;
  __u32 dst_ip4;
  __u32 src_ip4;
  __u32 dst_ip6[4];
  __u32 src_ip6[4];
  __u32 src_port;
  __be16 dst_port;
  __u32 identity;
};

static __always_inline void marshal(struct event_t *event,
                                    const struct bpf_sock *sk) {
  if (!sk || !event) {
    return;
  }
  event->sk_protocol = sk->protocol;
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


#endif
