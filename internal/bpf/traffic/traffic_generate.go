package traffic

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event_t -cc $BPF_CLANG -cflags $BPF_CFLAGS pod_traffic pod_traffic.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event_t -cc $BPF_CLANG -cflags $BPF_CFLAGS host_traffic host_traffic.c -- -I../headers
