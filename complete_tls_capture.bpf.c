#include "simple_bpf_types.h"

// XDP return codes
#define XDP_PASS 2
#define XDP_DROP 1

// TLS record types
#define TLS_CHANGE_CIPHER_SPEC 20
#define TLS_ALERT 21
#define TLS_HANDSHAKE 22
#define TLS_APPLICATION_DATA 23

// TLS versions
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

// TLS record header
struct tls_record_header {
    __u8 type;
    __u16 version;
    __u16 length;
} __attribute__((packed));

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
struct bpf_map_def SEC("maps") flow_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_state),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") key_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct ssl_key_info),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") packet_ringbuf = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
};

// Helper function to check if it's TLS traffic
static inline int is_tls_traffic(struct flow_key *flow) {
    return (flow->dst_port == 443 || flow->src_port == 443 ||
            flow->dst_port == 8443 || flow->src_port == 8443);
}

// Helper function to parse TLS header
static inline int parse_tls_header(void *data, void *data_end, struct tls_record_header *tls_hdr) {
    __u8 *bytes = (__u8 *)data;
    
    if ((void *)bytes + 5 > data_end)
        return -1;
    
    tls_hdr->type = bytes[0];
    tls_hdr->version = (bytes[1] << 8) | bytes[2];
    tls_hdr->length = (bytes[3] << 8) | bytes[4];
    
    // Validate TLS record type
    if (tls_hdr->type < TLS_CHANGE_CIPHER_SPEC || tls_hdr->type > TLS_APPLICATION_DATA)
        return -1;
    
    // Validate TLS version
    if (tls_hdr->version != TLS_VERSION_1_2 && tls_hdr->version != TLS_VERSION_1_3)
        return -1;
    
    return 0;
}

SEC("xdp")
int tls_packet_capture(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Basic packet size check
    if (data + 14 + 20 + 20 > data_end) // ETH + IP + TCP headers minimum
        return XDP_PASS;
    
    // Parse Ethernet header
    struct ethhdr *eth = (struct ethhdr *)data;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(data + 14);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Parse TCP header
    __u8 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60)
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    __u8 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > 60)
        return XDP_PASS;
    
    // Create flow key
    struct flow_key flow = {0};
    flow.src_ip = ip->saddr;
    flow.dst_ip = ip->daddr;
    flow.src_port = __builtin_bswap16(tcp->source);
    flow.dst_port = __builtin_bswap16(tcp->dest);
    flow.protocol = IPPROTO_TCP;
    
    // Check if it's TLS traffic
    if (!is_tls_traffic(&flow))
        return XDP_PASS;
    
    // Get or create flow state
    struct flow_state *state = bpf_map_lookup_elem(&flow_map, &flow);
    if (!state) {
        struct flow_state new_state = {0};
        new_state.last_seen = bpf_ktime_get_ns();
        bpf_map_update_elem(&flow_map, &flow, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&flow_map, &flow);
        if (!state)
            return XDP_PASS;
    }
    
    // Update last seen timestamp
    state->last_seen = bpf_ktime_get_ns();
    
    // Calculate payload pointer
    void *payload = (void *)tcp + tcp_hdr_len;
    if (payload >= data_end)
        return XDP_PASS;
    
    // Check for TLS record
    struct tls_record_header tls_hdr;
    if (parse_tls_header(payload, data_end, &tls_hdr) < 0)
        return XDP_PASS;
    
    // Reserve space in ring buffer
    struct packet_info *pkt_info = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(struct packet_info), 0);
    if (!pkt_info)
        return XDP_PASS;
    
    // Fill packet info
    pkt_info->flow = flow;
    pkt_info->seq_num = __builtin_bswap32(tcp->seq);
    pkt_info->ack_num = __builtin_bswap32(tcp->ack_seq);
    pkt_info->timestamp = bpf_ktime_get_ns();
    
    // Copy payload
    __u32 payload_len = data_end - payload;
    if (payload_len > 1500)
        payload_len = 1500;
    
    pkt_info->payload_len = payload_len;
    
    // Safe copy of payload
    for (int i = 0; i < 1500 && i < payload_len; i++) {
        if ((void *)((__u8 *)payload + i) >= data_end)
            break;
        pkt_info->payload[i] = ((__u8 *)payload)[i];
    }
    
    // Submit packet to ring buffer
    bpf_ringbuf_submit(pkt_info, 0);
    
    return XDP_PASS;
}

// License section
char _license[] SEC("license") = "GPL";
