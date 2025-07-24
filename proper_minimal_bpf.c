#include "simple_bpf_types.h"

#define XDP_PASS 2

__attribute__((section("xdp"), used))
int tls_packet_capture(struct xdp_md *ctx) {
    // For now, just pass all packets
    return XDP_PASS;
}

// License section
__attribute__((section("license"), used))
char _license[] = "GPL";
