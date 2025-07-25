// PCAP format fix - create proper Ethernet frames
#include "tls_capture.h"

// Ethernet header structure
struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6]; 
    uint16_t ethertype;
} __attribute__((packed));

// IP header structure (simplified)
struct ip_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

// TCP header structure (simplified)
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_flags;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

int write_packet_to_pcap(int pcap_fd, const struct packet_info *pkt) {
    if (pcap_fd < 0) return -1;
    
    // Create a proper Ethernet frame
    struct eth_header eth;
    struct ip_header ip;
    struct tcp_header tcp;
    
    // Fill Ethernet header (dummy MAC addresses)
    memset(eth.dst_mac, 0x00, 6);
    memset(eth.src_mac, 0x11, 6);
    eth.ethertype = htons(0x0800); // IPv4
    
    // Fill IP header
    ip.version_ihl = 0x45; // IPv4, 20 byte header
    ip.tos = 0;
    ip.total_length = htons(sizeof(ip) + sizeof(tcp) + pkt->payload_len);
    ip.id = htons(0x1234);
    ip.flags_fragment = 0;
    ip.ttl = 64;
    ip.protocol = 6; // TCP
    ip.checksum = 0; // We'll skip checksum calculation for simplicity
    ip.src_ip = pkt->src_ip;
    ip.dst_ip = pkt->dst_ip;
    
    // Fill TCP header
    tcp.src_port = pkt->src_port;
    tcp.dst_port = pkt->dst_port;
    tcp.seq_num = htonl(0x12345678); // Dummy sequence number
    tcp.ack_num = htonl(0x87654321); // Dummy ack number
    tcp.data_offset_flags = 0x50; // 20 byte header, no flags
    tcp.flags = 0x18; // PSH + ACK
    tcp.window = htons(65535);
    tcp.checksum = 0; // Skip checksum
    tcp.urgent_ptr = 0;
    
    // Calculate total packet size
    size_t total_size = sizeof(eth) + sizeof(ip) + sizeof(tcp) + pkt->payload_len;
    
    // Write PCAP packet header
    struct pcap_packet_header pkthdr;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    pkthdr.ts_sec = tv.tv_sec;
    pkthdr.ts_usec = tv.tv_usec;
    pkthdr.incl_len = total_size;
    pkthdr.orig_len = total_size;
    
    // Write packet header
    if (write(pcap_fd, &pkthdr, sizeof(pkthdr)) != sizeof(pkthdr)) {
        return -1;
    }
    
    // Write Ethernet header
    if (write(pcap_fd, &eth, sizeof(eth)) != sizeof(eth)) {
        return -1;
    }
    
    // Write IP header
    if (write(pcap_fd, &ip, sizeof(ip)) != sizeof(ip)) {
        return -1;
    }
    
    // Write TCP header
    if (write(pcap_fd, &tcp, sizeof(tcp)) != sizeof(tcp)) {
        return -1;
    }
    
    // Write payload
    if (pkt->payload_len > 0) {
        if (write(pcap_fd, pkt->payload, pkt->payload_len) != (ssize_t)pkt->payload_len) {
            return -1;
        }
    }
    
    fsync(pcap_fd);
    return 0;
}
