#include "simple_bpf_types.h"

// XDP return codes
#define XDP_PASS 2

// Flow key structure
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

// Flow state structure
struct flow_state {
    __u32 client_seq;
    __u32 server_seq;
    __u8 tls_established;
    __u8 key_extracted;
    __u64 last_seen;
};

// SSL key information
struct ssl_key_info {
    __u8 master_secret[48];
    __u8 client_random[32];
    __u8 server_random[32];
    __u16 cipher_suite;
    __u64 timestamp;
    __u32 valid;
};

// Packet information
struct packet_info {
    struct flow_key flow;
    __u32 seq_num;
    __u32 ack_num;
    __u16 payload_len;
    __u8 payload[1500];
    __u64 timestamp;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct flow_key);
    __type(value, struct ssl_key_info);
} key_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} packet_ringbuf SEC(".maps");

// XDP program
__attribute__((section("xdp"), used))
int tls_packet_capture(struct xdp_md *ctx) {
    // For now, just pass all packets
    return XDP_PASS;
}

// License section
__attribute__((section("license"), used))
char _license[] = "GPL";
