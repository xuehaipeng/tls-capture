#include "tls_capture.h"
#include <net/if.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

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
    
    // Close PCAP file if it's open
    if (pcap_fd >= 0) {
        close(pcap_fd);
        pcap_fd = -1;
    }
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
    
    // Set the target_port global variable in the BPF program
    struct bpf_map *port_map = bpf_object__find_map_by_name(obj, "target_port");
    if (port_map) {
        err = bpf_map__set_initial_value(port_map, &target_port, sizeof(target_port));
        if (err) {
            fprintf(stderr, "Failed to set target_port in BPF program: %d\n", err);
            bpf_object__close(obj);
            return -1;
        }
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
    
    // Set map file descriptors (can be -1 if maps don't exist)
    flow_map_fd = flow_map ? bpf_map__fd(flow_map) : -1;
    key_map_fd = key_map ? bpf_map__fd(key_map) : -1;
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
    int err = bpf_xdp_attach(ifindex, bpf_prog_fd, XDP_FLAGS_REPLACE, NULL);
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

static int handle_packet(void *ctx, void *data, size_t data_sz) {
    struct packet_info *pkt = (struct packet_info *)data;
    struct ssl_key_info key_info;
    char decrypted_data[MAX_PACKET_SIZE];
    int ret;
    
    // Print basic packet info
    printf("Captured TLS packet: %s:%d -> %s:%d, len=%d\n",
           inet_ntoa(*(struct in_addr*)&pkt->flow.src_ip), ntohs(pkt->flow.src_port),
           inet_ntoa(*(struct in_addr*)&pkt->flow.dst_ip), ntohs(pkt->flow.dst_port),
           pkt->payload_len);
    
    // Write packet to PCAP file if it's open
    if (pcap_fd >= 0) {
        struct pcap_packet_header pkthdr;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        
        pkthdr.ts_sec = tv.tv_sec;
        pkthdr.ts_usec = tv.tv_usec;
        pkthdr.incl_len = pkt->payload_len;
        pkthdr.orig_len = pkt->payload_len;
        
        // Write packet header
        ssize_t written = write(pcap_fd, &pkthdr, sizeof(pkthdr));
        if (written == sizeof(pkthdr)) {
            // Write packet data
            write(pcap_fd, pkt->payload, pkt->payload_len);
            fsync(pcap_fd); // Ensure data is written to disk
        }
    }
    
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
        
        // Try to detect if this is HTTP traffic
        if (tls_hdr.type == TLS_APPLICATION_DATA) {
            printf("🔍 TLS Application Data detected (potential HTTP content)\n");
        }
    }
    
    // Look up SSL keys for this flow (only if key_map exists)
    if (key_map_fd >= 0) {
        ret = bpf_map_lookup_elem(key_map_fd, &pkt->flow, &key_info);
        if (ret == 0 && key_info.valid) {
            // Attempt to decrypt the packet
            ret = decrypt_tls_data(pkt, &key_info, decrypted_data, sizeof(decrypted_data));
            if (ret > 0) {
                printf("🔓 Decrypted TLS data (%d bytes):\n", ret);
                
                // Check if decrypted data looks like HTTP
                if (ret > 4 && (strncmp(decrypted_data, "GET ", 4) == 0 || 
                               strncmp(decrypted_data, "POST", 4) == 0 ||
                               strncmp(decrypted_data, "HTTP", 4) == 0 ||
                               strncmp(decrypted_data, "HEAD", 4) == 0 ||
                               strncmp(decrypted_data, "PUT ", 4) == 0 ||
                               strncmp(decrypted_data, "DELE", 4) == 0)) {
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
                    print_decrypted_data(decrypted_data, ret);
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
            printf("🔐 No SSL keys found for this flow (encrypted traffic)\n");
            printf("💡 To decrypt: Use -p <pid> to hook SSL process or provide keys manually\n");
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
        printf("🔒 Encrypted TLS traffic (no key mapping available)\n");
        printf("💡 To decrypt: Use -p <pid> to hook SSL process or provide keys manually\n");
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
        // Just return, cleanup_and_exit will be called by signal handlers
        return 1;
    }
    
    // Initialize PCAP file if specified
    if (pcap_file) {
        if (init_pcap_file(pcap_file) < 0) {
            fprintf(stderr, "Failed to initialize PCAP file\n");
            detach_xdp_program(ifindex);
            // Just return, cleanup_and_exit will be called by signal handlers
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
                // Check if it's a recoverable error
                if (err == -EAGAIN || err == -EWOULDBLOCK) {
                    continue; // Non-fatal, continue polling
                }
                fprintf(stderr, "Error polling ring buffer: %d\n", err);
                // Don't break on error, continue polling
                // This prevents the tool from exiting on transient errors
                usleep(10000); // Sleep 10ms to avoid busy loop
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
