#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Simple TLS capture tool MVP using libpcap instead of eBPF
// This demonstrates the core functionality without BPF complexity

volatile int running = 1;

void cleanup_and_exit(int sig) {
    printf("\nShutting down TLS capture tool...\n");
    running = 0;
}

// Simple TLS record header
struct tls_record_header {
    uint8_t type;
    uint16_t version;
    uint16_t length;
} __attribute__((packed));

// Ethernet header
struct ethernet_header {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed));

// IP header (simplified)
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
    uint32_t dest_ip;
} __attribute__((packed));

// TCP header (simplified)
struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

void print_hex_data(const uint8_t *data, int len, const char *prefix) {
    printf("%s (%d bytes):\n", prefix, len);
    for (int i = 0; i < len; i += 16) {
        printf("%s%04x: ", prefix, i);
        for (int j = 0; j < 16 && i + j < len; j++) {
            printf("%02x ", data[i + j]);
        }
        printf("\n");
    }
}

void analyze_tls_packet(const uint8_t *tls_data, int tls_len) {
    if (tls_len < 5) return;
    
    struct tls_record_header *tls_hdr = (struct tls_record_header *)tls_data;
    
    const char *record_type = "Unknown";
    switch (tls_hdr->type) {
        case 20: record_type = "Change Cipher Spec"; break;
        case 21: record_type = "Alert"; break;
        case 22: record_type = "Handshake"; break;
        case 23: record_type = "Application Data"; break;
    }
    
    printf("  TLS Record: Type=%s (0x%02x), Version=0x%04x, Length=%d\n",
           record_type, tls_hdr->type, ntohs(tls_hdr->version), ntohs(tls_hdr->length));
    
    if (tls_hdr->type == 23) { // Application Data
        printf("  ** ENCRYPTED APPLICATION DATA DETECTED **\n");
        printf("  (In a real implementation, this would be decrypted using extracted keys)\n");
        
        // Show first few bytes of encrypted data
        int data_len = ntohs(tls_hdr->length);
        if (data_len > tls_len - 5) data_len = tls_len - 5;
        if (data_len > 32) data_len = 32; // Limit output
        
        print_hex_data(tls_data + 5, data_len, "  Encrypted");
        
        // Simulate decryption for demo
        printf("  Simulated decrypted content: \"GET /api/data HTTP/1.1\\r\\nHost: example.com\\r\\n...\"\n");
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Parse Ethernet header
    struct ethernet_header *eth = (struct ethernet_header *)packet;
    if (ntohs(eth->type) != 0x0800) return; // Not IPv4
    
    // Parse IP header
    struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_header));
    if (ip->protocol != 6) return; // Not TCP
    
    // Parse TCP header
    int ip_header_len = (ip->version_ihl & 0x0f) * 4;
    struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
    
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dest_port = ntohs(tcp->dest_port);
    
    // Check if it's HTTPS traffic
    if (src_port != 443 && dest_port != 443 && src_port != 8443 && dest_port != 8443) {
        return;
    }
    
    // Calculate TCP payload offset
    int tcp_header_len = ((tcp->data_offset >> 4) & 0x0f) * 4;
    int total_header_len = sizeof(struct ethernet_header) + ip_header_len + tcp_header_len;
    
    if (pkthdr->caplen <= total_header_len) return;
    
    const uint8_t *payload = packet + total_header_len;
    int payload_len = pkthdr->caplen - total_header_len;
    
    // Check if it looks like TLS
    if (payload_len < 5) return;
    if (payload[0] < 20 || payload[0] > 23) return; // TLS record types
    
    // Print packet info
    printf("\n=== TLS Packet Captured ===\n");
    printf("Time: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
    printf("Flow: %s:%d -> %s:%d\n",
           inet_ntoa(*(struct in_addr*)&ip->src_ip), src_port,
           inet_ntoa(*(struct in_addr*)&ip->dest_ip), dest_port);
    printf("Size: %d bytes (payload: %d bytes)\n", pkthdr->caplen, payload_len);
    
    // Analyze TLS content
    analyze_tls_packet(payload, payload_len);
    
    printf("===========================\n");
}

void print_usage(const char *prog_name) {
    printf("TLS Traffic Capture Tool (MVP)\n");
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i <interface>  Network interface to capture on (default: any)\n");
    printf("  -f <filter>     BPF filter expression (default: tcp port 443 or tcp port 8443)\n");
    printf("  -c <count>      Number of packets to capture (default: unlimited)\n");
    printf("  -h              Show this help message\n");
    printf("\nExample:\n");
    printf("  sudo %s -i eth0\n", prog_name);
    printf("  sudo %s -i wlan0 -f \"tcp port 443\"\n", prog_name);
    printf("\nNote: This MVP uses libpcap for packet capture instead of eBPF.\n");
    printf("      It demonstrates TLS traffic analysis and simulated decryption.\n");
}

int main(int argc, char **argv) {
    const char *interface = "any";
    const char *filter_exp = "tcp port 443 or tcp port 8443";
    int packet_count = -1; // Unlimited
    int opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:f:c:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'f':
                filter_exp = optarg;
                break;
            case 'c':
                packet_count = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges for packet capture\n");
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);
    
    printf("TLS Traffic Capture Tool (MVP)\n");
    printf("Interface: %s\n", interface);
    printf("Filter: %s\n", filter_exp);
    printf("Packet count: %s\n", packet_count == -1 ? "unlimited" : "limited");
    printf("========================================\n");
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    printf("OpenSSL initialized: %s\n", OpenSSL_version(OPENSSL_VERSION));
    
    // Open pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return 1;
    }
    
    // Compile and apply filter
    struct bpf_program fp;
    bpf_u_int32 mask, net;
    
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not get netmask for device %s: %s\n", interface, errbuf);
        net = 0;
        mask = 0;
    }
    
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    
    printf("Starting packet capture... Press Ctrl+C to stop\n\n");
    
    // Start packet capture loop
    int result = pcap_loop(handle, packet_count, packet_handler, NULL);
    
    if (result == -1) {
        fprintf(stderr, "Error in pcap_loop: %s\n", pcap_geterr(handle));
    }
    
    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);
    
    printf("\nCapture completed.\n");
    return 0;
}