#include "tls_capture.h"
#include <net/if.h>
#include <linux/if_link.h>
#include <fcntl.h>
#include <sys/stat.h>

// Global variables
volatile int running = 1;
int bpf_prog_fd = -1;
int flow_map_fd = -1;
int key_map_fd = -1;
int packet_ringbuf_fd = -1;
int port_filter_fd = -1;
struct bpf_object *obj = NULL;
struct ring_buffer *rb = NULL;

void cleanup_and_exit(int sig) {
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
}

int load_bpf_program(const char *filename) {
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
    
    // Get map file descriptors (optional for minimal BPF program)
    struct bpf_map *flow_map = bpf_object__find_map_by_name(obj, "flow_map");
    struct bpf_map *key_map = bpf_object__find_map_by_name(obj, "key_map");
    struct bpf_map *packet_ringbuf = bpf_object__find_map_by_name(obj, "packet_ringbuf");
    struct bpf_map *port_filter = bpf_object__find_map_by_name(obj, "port_filter");
    
    // Set map file descriptors (can be -1 if maps don't exist)
    flow_map_fd = flow_map ? bpf_map__fd(flow_map) : -1;
    key_map_fd = key_map ? bpf_map__fd(key_map) : -1;
    packet_ringbuf_fd = packet_ringbuf ? bpf_map__fd(packet_ringbuf) : -1;
    port_filter_fd = port_filter ? bpf_map__fd(port_filter) : -1;
    
    printf("BPF program loaded successfully\n");
    return 0;
}

int attach_xdp_program(const char *interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", interface);
        return -1;
    }
    
    // Try to attach with XDP_FLAGS_UPDATE_IF_NOEXIST first
    int err = bpf_xdp_attach(ifindex, bpf_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err == -EBUSY) {
        // If busy, try to detach existing program and attach new one
        printf("XDP program already attached to %s, detaching...\n", interface);
        err = bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        if (err) {
            fprintf(stderr, "Failed to detach existing XDP program from %s: %d\n", interface, err);
            return -1;
        }
        
        // Now try to attach the new program
        err = bpf_xdp_attach(ifindex, bpf_prog_fd, XDP_FLAGS_REPLACE, NULL);
        if (err) {
            fprintf(stderr, "Failed to attach XDP program to %s after detach: %d\n", interface, err);
            return -1;
        }
    } else if (err) {
        fprintf(stderr, "Failed to attach XDP program to %s: %d\n", interface, err);
        return -1;
    }
    
    printf("XDP program attached to interface %s\n", interface);
    return ifindex;
}

void detach_xdp_program(int ifindex) {
    bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    printf("XDP program detached\n");
}

// PCAP file header structure
struct pcap_file_header {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
};

// PCAP packet header structure
struct pcap_packet_header {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

// Create a new PCAP file with header
int create_pcap_file(const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to create PCAP file");
        return -1;
    }
    
    // Write PCAP file header
    struct pcap_file_header header = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1  // Ethernet
    };
    
    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        perror("Failed to write PCAP header");
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    return 0;
}

// Save a packet to PCAP file
int save_packet_to_pcap(const struct packet_info *pkt, const char *filename) {
    FILE *fp = fopen(filename, "ab");
    if (!fp) {
        perror("Failed to open PCAP file for writing");
        return -1;
    }
    
    // Get current time
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    // Create Ethernet frame (simplified)
    // In a real implementation, we would reconstruct the full Ethernet frame
    // For now, we'll just save the payload with a minimal Ethernet header
    
    // Write PCAP packet header
    struct pcap_packet_header pkt_header = {
        .ts_sec = ts.tv_sec,
        .ts_usec = ts.tv_nsec / 1000,
        .incl_len = pkt->payload_len + 14,  // +14 for Ethernet header
        .orig_len = pkt->payload_len + 14
    };
    
    if (fwrite(&pkt_header, sizeof(pkt_header), 1, fp) != 1) {
        perror("Failed to write PCAP packet header");
        fclose(fp);
        return -1;
    }
    
    // Write minimal Ethernet header (14 bytes)
    uint8_t eth_header[14] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Destination MAC (fake)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source MAC (fake)
        0x08, 0x00                           // EtherType (IPv4)
    };
    
    if (fwrite(eth_header, sizeof(eth_header), 1, fp) != 1) {
        perror("Failed to write Ethernet header");
        fclose(fp);
        return -1;
    }
    
    // Write packet payload
    if (fwrite(pkt->payload, pkt->payload_len, 1, fp) != 1) {
        perror("Failed to write packet payload");
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    return 0;
}

// Global variable to store PCAP filename
static const char *g_pcap_file = NULL;

static int handle_packet(void *ctx, void *data, size_t data_sz) {
    struct packet_info *pkt = (struct packet_info *)data;
    struct ssl_key_info key_info;
    char decrypted_data[MAX_PACKET_SIZE];
    int ret;
    
    // Debug: Print when we receive a packet in userspace
    printf("Userspace: Received packet from ring buffer - len=%zu\n", data_sz);
    
    // Save packet to PCAP file if specified
    if (g_pcap_file) {
        save_packet_to_pcap(pkt, g_pcap_file);
    }
    
    // Print basic packet info
    printf("Captured TLS packet: %s:%d -> %s:%d, len=%d\n",
           inet_ntoa(*(struct in_addr*)&pkt->flow.src_ip), ntohs(pkt->flow.src_port),
           inet_ntoa(*(struct in_addr*)&pkt->flow.dst_ip), ntohs(pkt->flow.dst_port),
           pkt->payload_len);
    
    // Parse TLS record header
    if (pkt->payload_len >= TLS_RECORD_HEADER_SIZE) {
        struct tls_record_header tls_hdr;
        tls_hdr.type = pkt->payload[0];
        tls_hdr.version = (pkt->payload[1] << 8) | pkt->payload[2];
        tls_hdr.length = (pkt->payload[3] << 8) | pkt->payload[4];
        
        printf("TLS Record: Type=%s, Version=%s, Length=%d\n",
               get_tls_record_type_name(tls_hdr.type),
               get_tls_version_name(tls_hdr.version),
               tls_hdr.length);
        
        // Try to decrypt and parse HTTP content if this is application data
        if (tls_hdr.type == TLS_APPLICATION_DATA) {
            printf("🔍 TLS Application Data detected (potential HTTP content)\n");
            
    // Look up SSL keys for this flow (only if key_map exists)
    if (key_map_fd >= 0) {
        ret = bpf_map_lookup_elem(key_map_fd, &pkt->flow, &key_info);
        if (ret == 0 && key_info.valid) {
            // Attempt to decrypt the packet
            ret = decrypt_tls_data(pkt, &key_info, decrypted_data, sizeof(decrypted_data));
            if (ret > 0) {
                printf("🔓 Decrypted TLS data (%d bytes):\n", ret);
                
                // Check if decrypted data looks like HTTP
                if (ret > 4 && (strncmp((char*)decrypted_data, "GET ", 4) == 0 || 
                               strncmp((char*)decrypted_data, "POST", 4) == 0 ||
                               strncmp((char*)decrypted_data, "HTTP", 4) == 0 ||
                               strncmp((char*)decrypted_data, "HEAD", 4) == 0 ||
                               strncmp((char*)decrypted_data, "PUT ", 4) == 0 ||
                               strncmp((char*)decrypted_data, "DELE", 4) == 0)) {
                    printf("🌐 HTTP Traffic Detected:\n");
                    printf("=== HTTP CONTENT ===\n");
                    // Print HTTP headers and body
                    for (int i = 0; i < ret && i < 1024; i++) {
                        putchar(decrypted_data[i]);
                        if (i > 4 && decrypted_data[i-3] == '\r' && decrypted_data[i-2] == '\n' &&
                            decrypted_data[i-1] == '\r' && decrypted_data[i] == '\n') {
                            // End of HTTP headers, add separator before body
                            printf("\n--- HTTP BODY ---\n");
                        }
                    }
                    if (ret > 1024) {
                        printf("\n... (truncated, %d more bytes)\n", ret - 1024);
                    }
                    printf("\n=== END HTTP CONTENT ===\n");
                } else {
                    // Not HTTP, show as generic decrypted data
                    print_decrypted_data((char*)decrypted_data, ret);
                }
            } else {
                printf("❌ Failed to decrypt packet (possibly wrong keys or encrypted with different parameters)\n");
                // Still show raw TLS data for debugging
                printf("Raw TLS data (first 64 bytes):\n");
                for (int i = 0; i < pkt->payload_len && i < 64; i++) {
                    printf("%02x ", pkt->payload[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                printf("\n");
            }
        } else {
            printf("No SSL keys found for this flow\n");
            // For debugging, let's try to decrypt with a mock key to see if the decryption logic works
            // This is just for demonstration purposes
            /*
            struct ssl_key_info mock_key = {0};
            mock_key.valid = 1;
            // Fill with fake key data for testing
            for (int i = 0; i < 48; i++) {
                mock_key.master_secret[i] = i;
            }
            for (int i = 0; i < 32; i++) {
                mock_key.client_random[i] = i;
                mock_key.server_random[i] = i + 32;
            }
            mock_key.cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
            
            // Attempt to decrypt with mock key
            ret = decrypt_tls_data(pkt, &mock_key, decrypted_data, sizeof(decrypted_data));
            if (ret > 0) {
                printf("🔓 Decrypted TLS data with mock key (%d bytes):\n", ret);
                print_decrypted_data((char*)decrypted_data, ret);
            } else {
                printf("❌ Failed to decrypt packet with mock key\n");
                // Print raw TLS data for debugging
                printf("Raw TLS data (first 64 bytes):\n");
                for (int i = 0; i < pkt->payload_len && i < 64; i++) {
                    printf("%02x ", pkt->payload[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                printf("\n");
            }
            */
            // Print raw TLS data for debugging
            printf("Raw TLS data (first 64 bytes):\n");
            for (int i = 0; i < pkt->payload_len && i < 64; i++) {
                printf("%02x ", pkt->payload[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
        }
    } else {
        // If no key map, just print raw TLS data
        printf("Raw TLS data (first 64 bytes):\n");
        for (int i = 0; i < pkt->payload_len && i < 64; i++) {
            printf("%02x ", pkt->payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }
        }
    } else {
        // If no TLS record header, just print raw data
        printf("Raw data (first 64 bytes):\n");
        for (int i = 0; i < pkt->payload_len && i < 64; i++) {
            printf("%02x ", pkt->payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }
    
    printf("----------------------------------------\n");
    return 0;
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i <interface>  Network interface to capture on (default: eth0)\n");
    printf("  -f <bpf_file>   BPF object file (default: tls_capture.bpf.o)\n");
    printf("  -p <pid>        Process ID to hook for SSL keys\n");
    printf("  -P <port>       Target port to capture (default: 443, 8443)\n");
    printf("  -w <file>       Write captured packets to PCAP file\n");
    printf("  -h              Show this help message\n");
    printf("\nEnvironment Variables:\n");
    printf("  SSLKEYLOGFILE   Path to SSL key log file for decryption\n");
    printf("\nExamples:\n");
    printf("  sudo %s -i eth0 -P 8443\n", prog_name);
    printf("  SSLKEYLOGFILE=/tmp/keys.txt sudo %s -i eth0 -w capture.pcap\n", prog_name);
}

int main(int argc, char **argv) {
    const char *interface = "eth0";
    const char *bpf_file = "tls_capture.bpf.o";
    const char *pcap_file = NULL;
    pid_t target_pid = 0;
    __u16 target_port = 0;
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
                target_port = (__u16)atoi(optarg);
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
    if (target_port > 0) {
        printf("Target Port: %d\n", target_port);
    } else {
        printf("Target Ports: 443, 8443 (default)\n");
    }
    if (pcap_file) {
        printf("PCAP file: %s\n", pcap_file);
        // Create PCAP file with header
        if (create_pcap_file(pcap_file) < 0) {
            fprintf(stderr, "Failed to create PCAP file\n");
            return 1;
        }
        // Set global PCAP file variable
        g_pcap_file = pcap_file;
    }
    printf("----------------------------------------\n");
    
    // Load BPF program
    if (load_bpf_program(bpf_file) < 0) {
        return 1;
    }
    
    // Attach XDP program to interface
    ifindex = attach_xdp_program(interface);
    if (ifindex < 0) {
        // Just return, cleanup_and_exit will be called by signal handlers
        return 1;
    }
    
    // Set port filter if specified
    if (target_port > 0 && port_filter_fd >= 0) {
        __u32 key = 0;
        int ret = bpf_map_update_elem(port_filter_fd, &key, &target_port, BPF_ANY);
        if (ret == 0) {
            printf("Port filter set to: %d\n", target_port);
            
            // Verify the port filter was set correctly
            __u16 verify_port = 0;
            int verify_ret = bpf_map_lookup_elem(port_filter_fd, &key, &verify_port);
            if (verify_ret == 0) {
                printf("Port filter verification: %d (expected: %d)\n", verify_port, target_port);
            } else {
                printf("Warning: Failed to verify port filter: %d\n", verify_ret);
            }
        } else {
            printf("Warning: Failed to set port filter: %d\n", ret);
        }
    } else if (target_port > 0) {
        printf("Warning: Port filter specified but BPF map not available\n");
    }
    
    // Debug: Print target_port and port_filter_fd values
    printf("Debug: target_port=%d, port_filter_fd=%d\n", target_port, port_filter_fd);
    
    // Set up SSL hooks and SSLKEYLOGFILE monitoring
    printf("Setting up SSL hooks and SSLKEYLOGFILE monitoring...\n");
    if (setup_ssl_hooks() < 0) {
        fprintf(stderr, "Warning: Failed to set up SSL hooks\n");
    }
    
    // Additional setup for target PID if specified
    if (target_pid > 0) {
        printf("Target PID specified: %d\n", target_pid);
        // SSL hooks already set up above
    }
    
    // Set up ring buffer for receiving packets (only if packet_ringbuf exists)
    if (packet_ringbuf_fd >= 0) {
        rb = ring_buffer__new(packet_ringbuf_fd, handle_packet, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            detach_xdp_program(ifindex);
            // Just return, cleanup_and_exit will be called by signal handlers
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
    
    return 0;
}
