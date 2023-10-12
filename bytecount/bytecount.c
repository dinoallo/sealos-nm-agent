// clang-format off
//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

// clang-format on
char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 65536);
} ipv4_ingress_bytecount_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 65536);
} ipv4_egress_bytecount_map SEC(".maps");

#define __ctx_buff __sk_buff

static __always_inline void
ipv4_ingress_update_bytecount(const struct __ctx_buff *ctx, u32 identity) {
  u64 len, *bytecount;
  len = ctx->len;
  bytecount = bpf_map_lookup_elem(&ipv4_ingress_bytecount_map, &identity);
  if (bytecount)
    __sync_fetch_and_add(bytecount, len);
  else
    bpf_map_update_elem(&ipv4_ingress_bytecount_map, &identity, &len, BPF_ANY);
}

static __always_inline void
ipv4_egress_update_bytecount(const struct __ctx_buff *ctx, u32 identity) {
  u64 len, *bytecount;
  len = ctx->len;
  bytecount = bpf_map_lookup_elem(&ipv4_egress_bytecount_map, &identity);
  if (bytecount)
    __sync_fetch_and_add(bytecount, len);
  else
    bpf_map_update_elem(&ipv4_egress_bytecount_map, &identity, &len, BPF_ANY);
}

SEC("classifier")
int ipv4_ingress_bytecount_custom_hook(const struct __ctx_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;
  int ret = (custom_meta >> 24) & 0xff;

  ipv4_ingress_update_bytecount(ctx, identity);

  return ret;
}

SEC("classifier")
int ipv4_egress_bytecount_custom_hook(const struct __ctx_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;
  int ret = (custom_meta >> 24) & 0xff;

  ipv4_egress_update_bytecount(ctx, identity);

  return ret;
}
