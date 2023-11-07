package bytecount

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type traffic_event_t -cc $BPF_CLANG -cflags $BPF_CFLAGS bytecount bytecount.c -- -I../headers
