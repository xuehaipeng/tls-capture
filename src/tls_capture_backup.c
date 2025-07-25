#include "tls_capture.h"
#include <net/if.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

// PCAP file format constants
#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_MAJOR_VERSION 2
#define PCAP_MINOR_VERSION 4
#define PCAP_TIMEZONE_UTC 0
#define PCAP_ACCURACY 0
#define PCAP_SNAPLEN 65535

// Global variables
volatile int running = 1;
int bpf_prog_fd = -1;
int flow_map_fd = -1;
int key_map_fd = -1;
int packet_ringbuf_fd = -1;
int pcap_fd = -1;
struct bpf_object *obj = NULL;
struct ring_buffer *rb = NULL;

// PCAP file header structure
struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

// PCAP packet header structure
struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

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

// Simple packet info structure to match BPF program

void cleanup_and_exit(int sig) {
    (void)sig; // Suppress unused parameter warning
    printf("\nShutting down TLS capture tool...\n");
    running = 0;
    
    // Cleanup SSL hooks
    cleanup_ssl_hooks();
    
    // Cleanup ring buffer if it exists
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
    
    // Cleanup BPF object if it exists
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
    
    // Close PCAP file if it's open
    if (pcap_fd >= 0) {
        close(pcap_fd);
        pcap_fd = -1;
    }
}

// HTTP parsing functions
int is_http_request(const char *data, size_t len) {
    if (len < 4) return 0;
    return (strncmp(data, "GET ", 4) == 0 ||
            strncmp(data, "POST", 4) == 0 ||
            strncmp(data, "PUT ", 4) == 0 ||
            strncmp(data, "HEAD", 4) == 0 ||
            strncmp(data, "DELE", 4) == 0 ||
            strncmp(data, "OPTI", 4) == 0 ||
            strncmp(data, "PATC", 4) == 0);
}

int is_http_response(const char *data, size_t len) {
    if (len < 8) return 0;
    return strncmp(data, "HTTP/", 5) == 0;
}

void parse_and_display_http(const char *data, size_t len) {
    if (!data || len == 0) return;
    
    printf("\n=== HTTP CONTENT DETECTED ===\n");
    
    // Find end of headers (double CRLF)
    const char *header_end = strstr(data, "\r\n\r\n");
    if (!header_end) {
        header_end = strstr(data, "\n\n");
        if (header_end) header_end += 2;
    } else {
        header_end += 4;
    }
    
    // Display headers
    if (header_end) {
        size_t header_len = header_end - data;
        printf("HTTP Headers:\n");
        printf("----------------------------------------\n");
        
        // Print headers line by line
        const char *line_start = data;
        for (size_t i = 0; i < header_len; i++) {
            if (data[i] == '\n') {
                // Print the line
                size_t line_len = &data[i] - line_start;
                if (line_len > 0 && data[i-1] == '\r') line_len--;
                printf("%.*s\n", (int)line_len, line_start);
                line_start = &data[i + 1];
            }
        }
        
        // Display body if present
        const char *body = header_end;
        size_t body_len = len - (body - data);
        
        if (body_len > 0) {
            printf("\nHTTP Body (%zu bytes):\n", body_len);
            printf("----------------------------------------\n");
            
            // Check if body is text-based
            int is_text = 1;
            for (size_t i = 0; i < body_len && i < 100; i++) {
                if (!isprint(body[i]) && !isspace(body[i])) {
                    is_text = 0;
                    break;
                }
            }
            
            if (is_text) {
                // Display as text (limit to reasonable size)
                size_t display_len = body_len > 1000 ? 1000 : body_len;
                printf("%.*s", (int)display_len, body);
                if (body_len > 1000) {
                    printf("\n... (truncated, %zu more bytes)", body_len - 1000);
                }
                printf("\n");
            } else {
                printf("[Binary content - %zu bytes]\n", body_len);
                // Show hex dump of first 64 bytes
                printf("First 64 bytes (hex):\n");
                for (size_t i = 0; i < body_len && i < 64; i++) {
                    printf("%02x ", (unsigned char)body[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                if (body_len > 0 && (body_len % 16) != 0) printf("\n");
            }
        }
    } else {
        // No clear header/body separation, just display as is
        printf("Raw HTTP Data:\n");
        printf("----------------------------------------\n");
        size_t display_len = len > 500 ? 500 : len;
        printf("%.*s", (int)display_len, data);
        if (len > 500) {
            printf("\n... (truncated, %zu more bytes)", len - 500);
        }
        printf("\n");
    }
    
    printf("=== END HTTP CONTENT ===\n\n");
}

int write_packet_to_pcap(int fd, const struct simple_packet_info *pkt) {
    if (fd < 0) return -1;
    
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
    if (write(fd, &pkthdr, sizeof(pkthdr)) != sizeof(pkthdr)) {
        return -1;
    }
    
    // Write Ethernet header
    if (write(fd, &eth, sizeof(eth)) != sizeof(eth)) {
        return -1;
    }
    
    // Write IP header
    if (write(fd, &ip, sizeof(ip)) != sizeof(ip)) {
        return -1;
    }
    
    // Write TCP header
    if (write(fd, &tcp, sizeof(tcp)) != sizeof(tcp)) {
        return -1;
    }
    
    // Write payload
    if (pkt->payload_len > 0) {
        if (write(fd, pkt->payload, pkt->payload_len) != (ssize_t)pkt->payload_len) {
            return -1;
        }
    }
    
    fsync(fd);
    return 0;
}

static int handle_packet(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz; // Suppress unused parameter warnings
    struct simple_packet_info *pkt = (struct simple_packet_info *)data;
    
    // Print basic packet info
    printf("Captured TLS packet: %s:%d -> %s:%d, len=%d\n",
           inet_ntoa(*(struct in_addr*)&pkt->src_ip), ntohs(pkt->src_port),
           inet_ntoa(*(struct in_addr*)&pkt->dst_ip), ntohs(pkt->dst_port),
           pkt->payload_len);
    
    // Write packet to PCAP file if it's open
    if (pcap_fd >= 0 && write_packet_to_pcap(pcap_fd, pkt) < 0) {
        printf("Warning: Failed to write packet to PCAP file\n");
    }
    
    // Try to parse as HTTP content (check if payload looks like plaintext HTTP)
    if (pkt->payload_len >= 4 && 
        (is_http_request((char*)pkt->payload, pkt->payload_len) ||
         is_http_response((char*)pkt->payload, pkt->payload_len))) {
        parse_and_display_http((char*)pkt->payload, pkt->payload_len);
    } else {
        // Parse TLS record header
        if (pkt->payload_len >= 5) { // TLS record header is 5 bytes
            uint8_t type = pkt->payload[0];
            uint16_t version = (pkt->payload[1] << 8) | pkt->payload[2];
            uint16_t length = (pkt->payload[3] << 8) | pkt->payload[4];
            
            const char* type_name = "Unknown";
            switch(type) {
                case 20: type_name = "Change Cipher Spec"; break;
                case 21: type_name = "Alert"; break;
                case 22: type_name = "Handshake"; break;
                case 23: type_name = "Application Data"; break;
            }
            
            const char* version_name = "Unknown";
            switch(version) {
                case 0x0301: version_name = "TLS 1.0"; break;
                case 0x0302: version_name = "TLS 1.1"; break;
                case 0x0303: version_name = "TLS 1.2"; break;
                case 0x0304: version_name = "TLS 1.3"; break;
            }
            
            printf("TLS Record: Type=%s, Version=%s, Length=%d\n",
                   type_name, version_name, length);
        }
        
        // Print raw TLS data for debugging
        printf("Raw TLS data (first 64 bytes):\n");
        for (int i = 0; i < pkt->payload_len && i < 64; i++) {
            printf("%02x ", pkt->payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }
    
    printf("----------------------------------------\n");
    return 0;
}

int load_bpf_program(const char *filename, __u16 target_port) {
    struct bpf_program *prog;
    int err;
    
    // Load BPF object
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", filename);
        return -1;
    }
    
    // Load BPF program into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }
    
    // Find the XDP program
    prog = bpf_object__find_program_by_name(obj, "tls_packet_capture");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return -1;
    }
    
    bpf_prog_fd = bpf_program__fd(prog);
    
    // Get map file descriptors
    struct bpf_map *packet_ringbuf = bpf_object__find_map_by_name(obj, "packet_ringbuf");
    packet_ringbuf_fd = packet_ringbuf ? bpf_map__fd(packet_ringbuf) : -1;
    
    printf("BPF program loaded successfully (target port: %d)\n", target_port);
    return 0;
}

int attach_xdp_program(const char *interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", interface);
        return -1;
    }
    
    // First, try to detach any existing XDP program
    printf("Detaching any existing XDP program from %s...\n", interface);
    bpf_xdp_detach(ifindex, 0, NULL);
    
    // Now try to attach the new program
    int err = bpf_xdp_attach(ifindex, bpf_prog_fd, 0, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to %s: %d\n", interface, err);
        return -1;
    }
    
    printf("XDP program attached to interface %s\n", interface);
    return ifindex;
}

void detach_xdp_program(int ifindex) {
    bpf_xdp_detach(ifindex, 0, NULL);
    printf("XDP program detached\n");
}

int init_pcap_file(const char *filename) {
    // Open PCAP file for writing
    pcap_fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (pcap_fd < 0) {
        perror("Failed to open PCAP file");
        return -1;
    }
    
    // Write PCAP file header
    struct pcap_file_header hdr;
    hdr.magic = PCAP_MAGIC;
    hdr.version_major = PCAP_MAJOR_VERSION;
    hdr.version_minor = PCAP_MINOR_VERSION;
    hdr.thiszone = PCAP_TIMEZONE_UTC;
    hdr.sigfigs = 0;
    hdr.snaplen = PCAP_SNAPLEN;
    hdr.linktype = 1; // LINKTYPE_ETHERNET
    
    ssize_t written = write(pcap_fd, &hdr, sizeof(hdr));
    if (written != sizeof(hdr)) {
        perror("Failed to write PCAP file header");
        close(pcap_fd);
        pcap_fd = -1;
        return -1;
    }
    
    printf("PCAP file initialized: %s\n", filename);
    return 0;
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i <interface>  Network interface to capture on (default: eth0)\n");
    printf("  -f <bpf_file>   BPF object file (default: tls_capture.bpf.o)\n");
    printf("  -p <pid>        Process ID to hook for SSL keys\n");
    printf("  -P <port>       Port to capture traffic on (default: 443)\n");
    printf("  -w <file>       Write captured packets to PCAP file\n");
    printf("  -h              Show this help message\n");
    printf("\nExample:\n");
    printf("  sudo %s -i eth0 -p 1234 -P 8443 -w capture.pcap\n", prog_name);
}

int main(int argc, char **argv) {
    const char *interface = "eth0";
    const char *bpf_file = "tls_capture.bpf.o";
    const char *pcap_file = NULL;
    pid_t target_pid = 0;
    __u16 target_port = 443;  // Default port
    int opt;
    int ifindex = -1;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:f:p:P:w:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'f':
                bpf_file = optarg;
                break;
            case 'p':
                target_pid = atoi(optarg);
                break;
            case 'P':
                target_port = atoi(optarg);
                break;
            case 'w':
                pcap_file = optarg;
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
        fprintf(stderr, "This program requires root privileges\n");
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);
    
    printf("TLS Traffic Capture Tool\n");
    printf("Interface: %s\n", interface);
    printf("BPF file: %s\n", bpf_file);
    if (target_pid > 0) {
        printf("Target PID: %d\n", target_pid);
    }
    printf("----------------------------------------\n");
    
    // Load BPF program
    if (load_bpf_program(bpf_file, target_port) < 0) {
        return 1;
    }
    
    // Attach XDP program to interface
    ifindex = attach_xdp_program(interface);
    if (ifindex < 0) {
        return 1;
    }
    
    // Initialize PCAP file if specified
    if (pcap_file) {
        if (init_pcap_file(pcap_file) < 0) {
            fprintf(stderr, "Failed to initialize PCAP file\n");
            detach_xdp_program(ifindex);
            return 1;
        }
    }
    
    // Set up SSL hooks if target PID is specified
    if (target_pid > 0) {
        printf("Setting up SSL hooks for PID %d...\n", target_pid);
        if (setup_ssl_hooks() < 0) {
            fprintf(stderr, "Warning: Failed to set up SSL hooks\n");
        }
    }
    
    // Set up ring buffer for receiving packets
    if (packet_ringbuf_fd >= 0) {
        rb = ring_buffer__new(packet_ringbuf_fd, handle_packet, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            detach_xdp_program(ifindex);
            return 1;
        }
        
        printf("Starting packet capture... Press Ctrl+C to stop\n");
        
        // Main event loop
        while (running) {
            int err = ring_buffer__poll(rb, 100); // 100ms timeout
            if (err == -EINTR) {
                break;
            }
            if (err < 0) {
                fprintf(stderr, "Error polling ring buffer: %d\n", err);
                break;
            }
        }
    } else {
        printf("BPF program loaded and attached, but no ring buffer available.\n");
        printf("Running in passive mode... Press Ctrl+C to stop\n");
        
        // Main event loop (passive mode)
        while (running) {
            sleep(1);
        }
    }
    
    // Cleanup
    if (ifindex >= 0) {
        detach_xdp_program(ifindex);
    }
    cleanup_and_exit(0);
    
    return 0;
}
