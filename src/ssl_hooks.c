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
static time_t last_file_mod_time = 0;

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
    
    // Setup SSLKEYLOGFILE monitoring
    if (setup_sslkeylog_monitoring() != 0) {
        printf("Warning: SSLKEYLOGFILE monitoring setup failed\n");
    }
    
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

// Parse SSLKEYLOGFILE entry and extract keys
int parse_sslkeylog_entry(const char *line, struct flow_key *flow, struct ssl_key_info *key_info) {
    char label[64];
    char client_random_hex[65];
    char key_hex[129];
    
    // Parse line format: "CLIENT_RANDOM <client_random> <master_secret>"
    if (sscanf(line, "%63s %64s %128s", label, client_random_hex, key_hex) != 3) {
        return -1;
    }
    
    // We only handle "CLIENT_RANDOM" entries for now
    if (strcmp(label, "CLIENT_RANDOM") != 0) {
        return -1;
    }
    
    // Convert hex strings to binary
    if (strlen(client_random_hex) != 64 || strlen(key_hex) > 96) {
        return -1;
    }
    
    // Convert client random from hex
    for (int i = 0; i < 32; i++) {
        sscanf(client_random_hex + i*2, "%2hhx", &key_info->client_random[i]);
    }
    
    // Convert master secret from hex
    int key_len = strlen(key_hex) / 2;
    if (key_len > 48) key_len = 48;
    
    for (int i = 0; i < key_len; i++) {
        sscanf(key_hex + i*2, "%2hhx", &key_info->master_secret[i]);
    }
    
    // For simplicity, we'll generate a mock server random
    // In a real implementation, we would need to associate this with a specific connection
    for (int i = 0; i < 32; i++) {
        key_info->server_random[i] = i + 0x80;
    }
    
    key_info->cipher_suite = 0x1301; // Default to TLS_AES_128_GCM_SHA256
    key_info->valid = 1;
    key_info->timestamp = time(NULL);
    
    printf("Parsed SSLKEYLOG entry: CLIENT_RANDOM %s\n", client_random_hex);
    return 0;
}

// Function to read and parse SSLKEYLOGFILE
int read_sslkeylog_file(void) {
    FILE *file;
    char line[512];
    int keys_loaded = 0;
    
    if (strlen(sslkeylog_file) == 0) {
        return 0;
    }
    
    // Check if file has been modified since last read
    struct stat file_stat;
    if (stat(sslkeylog_file, &file_stat) == 0) {
        if (file_stat.st_mtime <= last_file_mod_time) {
            // File hasn't been modified, no need to re-read
            return 0;
        }
        last_file_mod_time = file_stat.st_mtime;
    }
    
    file = fopen(sslkeylog_file, "r");
    if (!file) {
        return 0;
    }
    
    printf("Reading SSLKEYLOG file: %s\n", sslkeylog_file);
    
    while (fgets(line, sizeof(line), file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        struct flow_key flow = {0};
        struct ssl_key_info key_info = {0};
        
        if (parse_sslkeylog_entry(line, &flow, &key_info) == 0) {
            // Store the key in the BPF map for all possible flows
            // In a real implementation, we'd be more selective
            if (key_map_fd >= 0) {
                // Create a flow key that matches HTTPS traffic
                flow.dst_port = htons(443);
                flow.protocol = IPPROTO_TCP;
                
                int ret = bpf_map_update_elem(key_map_fd, &flow, &key_info, BPF_ANY);
                if (ret == 0) {
                    printf("✅ Stored SSL keys from SSLKEYLOGFILE\n");
                    keys_loaded++;
                } else {
                    printf("❌ Failed to store SSL keys: %d\n", ret);
                }
            }
        }
    }
    
    fclose(file);
    if (keys_loaded > 0) {
        printf("Loaded %d SSL keys from SSLKEYLOGFILE\n", keys_loaded);
    }
    return keys_loaded;
}

// Thread function to periodically check SSLKEYLOGFILE for updates
void* sslkeylog_monitor_thread(void* arg) {
    while (keylog_running) {
        read_sslkeylog_file();
        sleep(1); // Check every second
    }
    return NULL;
}

// Setup SSLKEYLOGFILE monitoring
int setup_sslkeylog_monitoring(void) {
    const char* keylog_env = getenv("SSLKEYLOGFILE");
    if (!keylog_env) {
        // Try to create a default SSLKEYLOGFILE
        strcpy(sslkeylog_file, "/tmp/sslkeylog.txt");
        setenv("SSLKEYLOGFILE", sslkeylog_file, 1);
        printf("Set SSLKEYLOGFILE to: %s\n", sslkeylog_file);
        printf("📝 To capture keys, run your HTTPS client with: SSLKEYLOGFILE=%s <your_command>\n", sslkeylog_file);
    } else {
        strcpy(sslkeylog_file, keylog_env);
        printf("Using existing SSLKEYLOGFILE: %s\n", sslkeylog_file);
    }
    
    // Create the file if it doesn't exist
    FILE* f = fopen(sslkeylog_file, "a");
    if (f) {
        fclose(f);
    } else {
        perror("Failed to create SSLKEYLOGFILE");
        return -1;
    }
    
    // Try to read existing keys
    read_sslkeylog_file();
    
    // Start monitoring thread
    keylog_running = 1;
    if (pthread_create(&keylog_thread, NULL, sslkeylog_monitor_thread, NULL) != 0) {
        perror("Failed to create SSLKEYLOGFILE monitoring thread");
        keylog_running = 0;
        return -1;
    }
    
    printf("✅ SSLKEYLOGFILE monitoring setup complete\n");
    return 0;
}

// Cleanup function
void cleanup_ssl_hooks(void) {
    // Stop keylog monitoring
    if (keylog_running) {
        keylog_running = 0;
        if (keylog_thread) {
            pthread_cancel(keylog_thread);
            pthread_join(keylog_thread, NULL);
        }
    }
    
    if (watch_fd >= 0) {
        inotify_rm_watch(inotify_fd, watch_fd);
        watch_fd = -1;
    }
    
    if (inotify_fd >= 0) {
        close(inotify_fd);
        inotify_fd = -1;
    }
    
    if (libssl_handle) {
        dlclose(libssl_handle);
        libssl_handle = NULL;
    }
    
    uprobe_attached = 0;
    printf("SSL hooks cleaned up\n");
}
