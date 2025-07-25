#include "tls_capture.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/inotify.h>
#include <pthread.h>

// Global variables for uprobe management
static int uprobe_attached = 0;
static void *libssl_handle = NULL;
static char sslkeylog_file[256] = {0};
static pthread_t keylog_thread;
static int keylog_running = 0;
static int inotify_fd = -1;
static int watch_fd = -1;

int setup_ssl_hooks(void) {
    printf("Setting up SSL hooks for key extraction...\n");
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    
    // Try to load libssl dynamically
    libssl_handle = dlopen("libssl.so.1.1", RTLD_LAZY);
    if (!libssl_handle) {
        libssl_handle = dlopen("libssl.so.3", RTLD_LAZY);
    }
    
    if (!libssl_handle) {
        fprintf(stderr, "Warning: Could not load libssl library: %s\n", dlerror());
        return -1;
    }
    
    printf("Successfully loaded SSL library\n");
    
    // In a full implementation, we would set up eBPF uprobes here
    // For now, we'll simulate the hooking mechanism
    uprobe_attached = 1;
    
    return 0;
}

// Function to extract SSL keys from an SSL structure
void extract_ssl_keys(SSL *ssl, struct ssl_key_info *key_info) {
    if (!ssl || !key_info) {
        return;
    }
    
    // Initialize key info structure
    memset(key_info, 0, sizeof(struct ssl_key_info));
    
    const SSL_SESSION *session = SSL_get_session(ssl);
    if (!session) {
        printf("No SSL session found\n");
        return;
    }
    
    // Extract master secret
    const unsigned char *master_secret_ptr = NULL;
    size_t master_secret_len = 0;
    
    // For OpenSSL 1.1.1 and later
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    unsigned char temp_master_secret[48];
    master_secret_len = SSL_SESSION_get_master_key(session, temp_master_secret, sizeof(temp_master_secret));
    master_secret_ptr = temp_master_secret;
#else
    // For older versions, we would need to access internal structures
    // This is not recommended but might be necessary for older OpenSSL versions
    master_secret_len = SSL_SESSION_get_master_key(session, NULL, 0);
    if (master_secret_len > 0) {
        // We can't directly access the master key in older versions without uprobe hooking
        printf("Warning: Cannot extract master key from older OpenSSL version without uprobe hooking\n");
        return;
    }
#endif
    
    if (master_secret_len == 0 || !master_secret_ptr) {
        printf("Failed to extract master secret\n");
        return;
    }
    
    // Copy master secret (limit to 48 bytes)
    size_t copy_len = master_secret_len > 48 ? 48 : master_secret_len;
    memcpy(key_info->master_secret, master_secret_ptr, copy_len);
    
    // Extract client and server random values
    size_t client_random_len = 0;
    size_t server_random_len = 0;
    
    // For OpenSSL 1.1.1 and later
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    client_random_len = SSL_get_client_random(ssl, key_info->client_random, 32);
    server_random_len = SSL_get_server_random(ssl, key_info->server_random, 32);
#else
    // For older versions, we would need to access internal structures
    printf("Warning: Cannot extract random values from older OpenSSL version without uprobe hooking\n");
    return;
#endif
    
    // Extract cipher suite
    const SSL_CIPHER *cipher = SSL_SESSION_get0_cipher((SSL_SESSION *)session);
    if (cipher) {
        key_info->cipher_suite = SSL_CIPHER_get_id(cipher) & 0xFFFF;
    } else {
        key_info->cipher_suite = 0x1301; // Default to TLS_AES_128_GCM_SHA256
    }
    
    key_info->valid = 1;
    key_info->timestamp = time(NULL);
    
    printf("SSL keys extracted successfully\n");
    printf("  Cipher Suite: 0x%04x\n", key_info->cipher_suite);
    printf("  Master Secret: %02x%02x%02x%02x...\n", 
           key_info->master_secret[0], key_info->master_secret[1], 
           key_info->master_secret[2], key_info->master_secret[3]);
}

// Enhanced hook function that would be called via eBPF uprobe
void ssl_key_extraction_hook(SSL *ssl, int is_write) {
    if (!ssl || !uprobe_attached) {
        return;
    }
    
    struct ssl_key_info key_info;
    struct flow_key flow = {0};
    
    // Extract SSL keys
    extract_ssl_keys(ssl, &key_info);
    
    // Get connection information
    int fd = SSL_get_fd(ssl);
    if (fd >= 0) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        
        if (getpeername(fd, (struct sockaddr*)&addr, &addr_len) == 0) {
            // Create flow key based on connection
            flow.dst_ip = addr.sin_addr.s_addr;
            flow.dst_port = addr.sin_port;
            flow.src_port = htons(fd); // Simplified - in real implementation we'd get actual src port
            flow.protocol = IPPROTO_TCP;
            
            // Store keys in BPF map
            if (key_map_fd >= 0) {
                int ret = bpf_map_update_elem(key_map_fd, &flow, &key_info, BPF_ANY);
                if (ret == 0) {
                    printf("Stored SSL keys for flow %s:%d\n", 
                           inet_ntoa(*(struct in_addr*)&flow.dst_ip), ntohs(flow.dst_port));
                } else {
                    printf("Failed to store SSL keys in BPF map: %d\n", ret);
                }
            }
        }
    }
}

// Function to simulate uprobe attachment for SSL_write
int attach_ssl_write_uprobe(void) {
    // In a real implementation, this would attach an eBPF uprobe to SSL_write
    // For demonstration, we'll just return success
    printf("Simulating SSL_write uprobe attachment\n");
    return 0;
}

// Function to simulate uprobe attachment for SSL_read
int attach_ssl_read_uprobe(void) {
    // In a real implementation, this would attach an eBPF uprobe to SSL_read
    // For demonstration, we'll just return success
    printf("Simulating SSL_read uprobe attachment\n");
    return 0;
}

// Cleanup function
void cleanup_ssl_hooks(void) {
    if (libssl_handle) {
        dlclose(libssl_handle);
        libssl_handle = NULL;
    }
    
    uprobe_attached = 0;
    printf("SSL hooks cleaned up\n");
}
