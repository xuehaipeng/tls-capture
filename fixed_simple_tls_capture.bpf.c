// Simplified BPF program for TLS capture
#include "simple_bpf_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XDP return codes
#define XDP_PASS 2

// Simple packet structure for ring buffer
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_len;
    __u8 payload[256];
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} packet_ringbuf SEC(".maps");

SEC("xdp")
int tls_packet_capture(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Basic packet size check
    if (data + 54 > data_end) // ETH + IP + TCP headers minimum
        return XDP_PASS;

    // Simple packet parsing (assuming Ethernet + IPv4 + TCP)
    __u8 *packet = (__u8 *)data;

    // Check if it's IPv4 (simplified)
    if (packet[12] != 0x08 || packet[13] != 0x00)
        return XDP_PASS;

    // Check if it's TCP (simplified)
    if (packet[23] != 6)
        return XDP_PASS;

    // Extract basic info (simplified parsing)
    __u32 src_ip = *(__u32 *)(packet + 26);
    __u32 dst_ip = *(__u32 *)(packet + 30);
    __u16 src_port = bpf_ntohs(*(__u16 *)(packet + 34));
    __u16 dst_port = bpf_ntohs(*(__u16 *)(packet + 36));

    // Check if it's HTTPS traffic (port 443 or 8443)
    if (src_port != 443 && dst_port != 443 &&
        src_port != 8443 && dst_port != 8443)
        return XDP_PASS;

    // Calculate payload offset (simplified)
    __u32 tcp_header_len = ((packet[46] >> 4) & 0x0f) * 4;
    __u32 payload_offset = 14 + 20 + tcp_header_len; // ETH + IP + TCP

    if (data + payload_offset > data_end)
        return XDP_PASS;

    // Check for TLS record (starts with 0x16, 0x17, etc.)
    __u8 *payload = packet + payload_offset;
    if (payload + 5 > (__u8 *)data_end)
        return XDP_PASS;

    if (payload[0] < 20 || payload[0] > 23) // TLS record types
        return XDP_PASS;

    // Reserve space in ring buffer
    struct packet_event *event = bpf_ringbuf_reserve(&packet_ringbuf,
                                                     sizeof(struct packet_event), 0);
    if (!event)
        return XDP_PASS;

    // Fill event data
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;

    // Calculate payload length using bpf helper to avoid pointer arithmetic
    __u32 payload_len = data_end - (void *)payload;
    if (payload_len > 256)
        payload_len = 256;

    event->payload_len = payload_len;

    // Safe copy using bpf_probe_read_kernel
    bpf_probe_read_kernel(event->payload, payload_len, payload);

    // Submit event
    bpf_ringbuf_submit(event, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
