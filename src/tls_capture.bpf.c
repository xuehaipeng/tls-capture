#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

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

SEC("xdp")
int tls_packet_capture(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u16 eth_type;
    __u8 ip_proto;
    __u16 tcp_source, tcp_dest;
    __u16 payload_len;
    void *payload;
    struct flow_key flow_key;
    struct flow_state *flow_state;
    struct flow_state new_flow_state = {0};
    struct packet_info *pkt_info;
    
    // Parse Ethernet header
    eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }
    
    eth_type = eth->h_proto;
    
    // Check for IPv4
    if (eth_type != 0x0800) {  // ETH_P_IP
        return XDP_PASS;
    }
    
    // Parse IP header
    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }
    
    // Check for TCP
    ip_proto = ip->protocol;
    if (ip_proto != IPPROTO_TCP) {
        return XDP_PASS;
    }
    
    // Parse TCP header
    __u8 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60) {
        return XDP_PASS;
    }
    
    tcp = (void *)ip + ip_hdr_len;
    if ((void *)tcp + sizeof(*tcp) > data_end) {
        return XDP_PASS;
    }
    
    // Get TCP ports
    tcp_source = tcp->source;
    tcp_dest = tcp->dest;
    
    // Check for HTTPS ports (443, 8443)
    if (tcp_source != 443 && tcp_source != 8443 && 
        tcp_dest != 443 && tcp_dest != 8443) {
        return XDP_PASS;
    }
    
    // Calculate TCP header length
    __u8 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > 60) {
        return XDP_PASS;
    }
    
    // Calculate payload
    payload = (void *)tcp + tcp_hdr_len;
    if (payload > data_end) {
        return XDP_PASS;
    }
    
    payload_len = data_end - payload;
    if (payload_len == 0) {
        return XDP_PASS;
    }
    
    // Check if it looks like TLS (first byte should be a valid TLS record type)
    __u8 *first_byte = payload;
    if (payload + 1 > data_end) {
        return XDP_PASS;
    }
    
    // TLS record types: 20-23
    if (*first_byte < 20 || *first_byte > 23) {
        return XDP_PASS;
    }
    
    // Create flow key
    flow_key.src_ip = ip->saddr;
    flow_key.dst_ip = ip->daddr;
    flow_key.src_port = tcp_source;
    flow_key.dst_port = tcp_dest;
    flow_key.protocol = ip_proto;
    
    // Look up or create flow state
    flow_state = bpf_map_lookup_elem(&flow_map, &flow_key);
    if (!flow_state) {
        new_flow_state.last_seen = bpf_ktime_get_ns();
        new_flow_state.client_seq = tcp->seq;
        bpf_map_update_elem(&flow_map, &flow_key, &new_flow_state, BPF_ANY);
    } else {
        flow_state->last_seen = bpf_ktime_get_ns();
    }
    
    // Reserve space in ring buffer for packet info
    pkt_info = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(struct packet_info), 0);
    if (!pkt_info) {
        return XDP_PASS;
    }
    
    // Copy flow key
    pkt_info->flow = flow_key;
    
    // Copy TCP sequence and ack numbers
    pkt_info->seq_num = tcp->seq;
    pkt_info->ack_num = tcp->ack_seq;
    
    // Copy payload (limited to MAX_PACKET_SIZE)
    __u16 copy_len = payload_len > 1500 ? 1500 : payload_len;
    if (payload + copy_len > data_end) {
        copy_len = data_end - payload;
    }
    
    // Limit copy length to prevent buffer overflow
    if (copy_len > 1500) {
        copy_len = 1500;
    }
    
    // Use bpf_probe_read_kernel for safer memory access
    long ret = bpf_probe_read_kernel(pkt_info->payload, copy_len, payload);
    if (ret != 0) {
        bpf_ringbuf_discard(pkt_info, 0);
        return XDP_PASS;
    }
    
    // Set payload length
    pkt_info->payload_len = copy_len;
    pkt_info->timestamp = bpf_ktime_get_ns();
    
    // Submit packet to ring buffer
    bpf_ringbuf_submit(pkt_info, 0);
    
    // Pass packet to kernel for normal processing
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
