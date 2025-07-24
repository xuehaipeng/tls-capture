#include "simple_bpf_types.h"

#define XDP_PASS 2
#define XDP_DROP 1

// Simple map definitions using the approach that works
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27

// XDP program
__attribute__((section("xdp"), used))
int tls_packet_capture(struct xdp_md *ctx) {
    // For now, just pass all packets
    // In a full implementation, this would capture and filter TLS packets
    return XDP_PASS;
}

// License section
__attribute__((section("license"), used))
char _license[] = "GPL";
