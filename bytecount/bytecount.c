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
  __uint(max_entries, 1024);
} bytecount_map SEC(".maps");

#define __ctx_buff __sk_buff

static __always_inline void update_bytecount(const struct __ctx_buff *ctx,
                                             u32 identity) {
  u64 len, *bytecount;
  len = ctx->len;
  bytecount = bpf_map_lookup_elem(&bytecount_map, &identity);
  if (bytecount)
    __sync_fetch_and_add(bytecount, len);
  else
    bpf_map_update_elem(&bytecount_map, &identity, &len, BPF_ANY);
}

SEC("classifier")
int custom_hook(const struct __ctx_buff *ctx) {
  u32 custom_meta = ctx->cb[4];
  u32 identity = custom_meta & 0xffffff;
  int ret = (custom_meta >> 24) & 0xff;

  update_bytecount(ctx, identity);

  return ret;
}
