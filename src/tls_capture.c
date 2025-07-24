#include "tls_capture.h"
#include <net/if.h>
#include <linux/if_link.h>

// Global variables
volatile int running = 1;
int bpf_prog_fd = -1;
int flow_map_fd = -1;
int key_map_fd = -1;
int packet_ringbuf_fd = -1;
struct bpf_object *obj = NULL;
struct ring_buffer *rb = NULL;

void cleanup_and_exit(int sig) {
    printf("\nShutting down TLS capture tool...\n");
    running = 0;
    
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
    
    // Set map file descriptors (can be -1 if maps don't exist)
    flow_map_fd = flow_map ? bpf_map__fd(flow_map) : -1;
    key_map_fd = key_map ? bpf_map__fd(key_map) : -1;
    packet_ringbuf_fd = packet_ringbuf ? bpf_map__fd(packet_ringbuf) : -1;
    
    printf("BPF program loaded successfully\n");
    return 0;
}

int attach_xdp_program(const char *interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", interface);
        return -1;
    }
    
    int err = bpf_xdp_attach(ifindex, bpf_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
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
    }
    
    // Look up SSL keys for this flow (only if key_map exists)
    if (key_map_fd >= 0) {
        ret = bpf_map_lookup_elem(key_map_fd, &pkt->flow, &key_info);
        if (ret == 0 && key_info.valid) {
            // Attempt to decrypt the packet
            ret = decrypt_tls_data(pkt, &key_info, decrypted_data, sizeof(decrypted_data));
            if (ret > 0) {
                printf("Decrypted data (%d bytes):\n", ret);
                print_decrypted_data(decrypted_data, ret);
            } else {
                printf("Failed to decrypt packet\n");
            }
        } else {
            printf("No SSL keys found for this flow\n");
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
    
    printf("----------------------------------------\n");
    return 0;
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i <interface>  Network interface to capture on (default: eth0)\n");
    printf("  -f <bpf_file>   BPF object file (default: tls_capture.bpf.o)\n");
    printf("  -p <pid>        Process ID to hook for SSL keys\n");
    printf("  -h              Show this help message\n");
    printf("\nExample:\n");
    printf("  sudo %s -i eth0 -p 1234\n", prog_name);
}

int main(int argc, char **argv) {
    const char *interface = "eth0";
    const char *bpf_file = "tls_capture.bpf.o";
    pid_t target_pid = 0;
    int opt;
    int ifindex = -1;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:f:p:h")) != -1) {
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
    if (load_bpf_program(bpf_file) < 0) {
        return 1;
    }
    
    // Attach XDP program to interface
    ifindex = attach_xdp_program(interface);
    if (ifindex < 0) {
        // Just return, cleanup_and_exit will be called by signal handlers
        return 1;
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
