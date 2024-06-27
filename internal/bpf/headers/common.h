// clang-format off
//go:build ignore
#ifndef _COMMON_H__
#define _COMMON_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

// clang-format on

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
  __u32 identity;
};


#endif
