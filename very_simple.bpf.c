#include "simple_bpf_types.h"

#define XDP_PASS 2

SEC("xdp")
int tls_packet_capture(struct xdp_md *ctx) {
    // For now, just pass all packets
    // In a full implementation, this would capture and filter TLS packets
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
