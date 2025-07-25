#include "simple_bpf_types.h"

// Define SEC macro for BPF section placement
#define SEC(name) __attribute__((section(name), used))

// XDP return codes
#define XDP_PASS 2

// Simple XDP program that just passes all packets
SEC("xdp")
int tls_packet_capture(struct xdp_md *ctx) {
    // For now, just pass all packets
    // In a full implementation, this would capture and filter TLS packets
    return XDP_PASS;
}

// License section
SEC("license")
char _license[] = "GPL";
