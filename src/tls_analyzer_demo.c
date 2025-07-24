#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

// TLS Traffic Analyzer Demo - Core functionality without packet capture
// This demonstrates the key concepts of TLS analysis and decryption

// TLS record types
#define TLS_CHANGE_CIPHER_SPEC 20
#define TLS_ALERT 21
#define TLS_HANDSHAKE 22
#define TLS_APPLICATION_DATA 23

// TLS versions
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

struct tls_record_header {
    uint8_t type;
    uint16_t version;
    uint16_t length;
} __attribute__((packed));

struct ssl_key_material {
    uint8_t master_secret[48];
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint16_t cipher_suite;
};

void print_hex(const char *label, const uint8_t *data, int len) {
    printf("%s (%d bytes):\n", label, len);
    for (int i = 0; i < len; i += 16) {
        printf("  %04x: ", i);
        for (int j = 0; j < 16 && i + j < len; j++) {
            printf("%02x ", data[i + j]);
        }
        printf("\n");
    }
}

void analyze_tls_record(const uint8_t *data, int len) {
    if (len < 5) {
        printf("Invalid TLS record (too short)\n");
        return;
    }
    
    struct tls_record_header *hdr = (struct tls_record_header *)data;
    
    const char *type_name = "Unknown";
    switch (hdr->type) {
        case TLS_CHANGE_CIPHER_SPEC: type_name = "Change Cipher Spec"; break;
        case TLS_ALERT: type_name = "Alert"; break;
        case TLS_HANDSHAKE: type_name = "Handshake"; break;
        case TLS_APPLICATION_DATA: type_name = "Application Data"; break;
    }
    
    const char *version_name = "Unknown";
    uint16_t version = (hdr->version >> 8) | (hdr->version << 8); // Fix endianness
    switch (version) {
        case TLS_VERSION_1_2: version_name = "TLS 1.2"; break;
        case TLS_VERSION_1_3: version_name = "TLS 1.3"; break;
    }
    
    uint16_t length = (hdr->length >> 8) | (hdr->length << 8); // Fix endianness
    
    printf("TLS Record Analysis:\n");
    printf("  Type: %s (0x%02x)\n", type_name, hdr->type);
    printf("  Version: %s (0x%04x)\n", version_name, version);
    printf("  Length: %d bytes\n", length);
    
    if (hdr->type == TLS_APPLICATION_DATA) {
        printf("  ** ENCRYPTED APPLICATION DATA **\n");
        printf("  This would contain encrypted HTTP/HTTPS traffic\n");
    }
}

int simulate_key_derivation(struct ssl_key_material *keys, uint8_t *encryption_key, uint8_t *mac_key) {
    printf("\nSimulating TLS Key Derivation:\n");
    
    // Generate simulated key material
    RAND_bytes(keys->master_secret, sizeof(keys->master_secret));
    RAND_bytes(keys->client_random, sizeof(keys->client_random));
    RAND_bytes(keys->server_random, sizeof(keys->server_random));
    keys->cipher_suite = 0x009C; // TLS_RSA_WITH_AES_128_GCM_SHA256
    
    print_hex("Master Secret", keys->master_secret, 16); // Show first 16 bytes
    print_hex("Client Random", keys->client_random, 16);
    print_hex("Server Random", keys->server_random, 16);
    
    // Simulate key derivation using HMAC-SHA256
    unsigned int len;
    HMAC(EVP_sha256(), keys->master_secret, sizeof(keys->master_secret),
         keys->client_random, sizeof(keys->client_random),
         encryption_key, &len);
    
    HMAC(EVP_sha256(), keys->master_secret, sizeof(keys->master_secret),
         keys->server_random, sizeof(keys->server_random),
         mac_key, &len);
    
    print_hex("Derived Encryption Key", encryption_key, 16);
    print_hex("Derived MAC Key", mac_key, 16);
    
    return 0;
}

int simulate_decryption(const uint8_t *encrypted_data, int encrypted_len,
                       const uint8_t *key, uint8_t *decrypted_data) {
    printf("\nSimulating TLS Decryption:\n");
    
    // For demo purposes, we'll simulate decryption by XORing with key
    // In real TLS, this would be AES-GCM or similar
    for (int i = 0; i < encrypted_len; i++) {
        decrypted_data[i] = encrypted_data[i] ^ key[i % 16];
    }
    
    // Simulate realistic HTTP content
    const char *http_content = "GET /api/user/profile HTTP/1.1\r\n"
                              "Host: api.example.com\r\n"
                              "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...\r\n"
                              "User-Agent: Mozilla/5.0 (Linux; Android 10)\r\n"
                              "Accept: application/json\r\n"
                              "\r\n";
    
    strncpy((char *)decrypted_data, http_content, encrypted_len - 1);
    decrypted_data[encrypted_len - 1] = '\0';
    
    return strlen(http_content);
}

void demo_tls_analysis() {
    printf("=== TLS Traffic Analysis Demo ===\n\n");
    
    // Simulate captured TLS records
    uint8_t tls_handshake[] = {
        0x16, 0x03, 0x03, 0x00, 0x40,  // TLS 1.2 Handshake, 64 bytes
        0x01, 0x00, 0x00, 0x3C,        // Client Hello
        // ... handshake data would follow
    };
    
    uint8_t tls_app_data[] = {
        0x17, 0x03, 0x03, 0x01, 0x00,  // TLS 1.2 Application Data, 256 bytes
        // ... encrypted application data would follow
    };
    
    printf("1. Analyzing TLS Handshake Record:\n");
    analyze_tls_record(tls_handshake, sizeof(tls_handshake));
    
    printf("\n2. Analyzing TLS Application Data Record:\n");
    analyze_tls_record(tls_app_data, sizeof(tls_app_data));
    
    // Simulate key extraction and derivation
    struct ssl_key_material keys;
    uint8_t encryption_key[32];
    uint8_t mac_key[32];
    
    printf("\n3. Key Material Extraction and Derivation:\n");
    simulate_key_derivation(&keys, encryption_key, mac_key);
    
    // Simulate decryption
    uint8_t encrypted_payload[256];
    uint8_t decrypted_payload[256];
    
    // Generate some "encrypted" data
    RAND_bytes(encrypted_payload, sizeof(encrypted_payload));
    
    printf("\n4. Decryption Process:\n");
    print_hex("Encrypted Payload (first 32 bytes)", encrypted_payload, 32);
    
    int decrypted_len = simulate_decryption(encrypted_payload, sizeof(encrypted_payload),
                                          encryption_key, decrypted_payload);
    
    printf("\nDecrypted Content:\n");
    printf("  Length: %d bytes\n", decrypted_len);
    printf("  Content: %s\n", decrypted_payload);
    
    printf("\n=== Analysis Complete ===\n");
}

void print_usage(const char *prog_name) {
    printf("TLS Traffic Analyzer Demo\n");
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -d              Run demonstration mode\n");
    printf("  -v              Verbose output\n");
    printf("  -h              Show this help message\n");
    printf("\nThis tool demonstrates:\n");
    printf("  - TLS record parsing and analysis\n");
    printf("  - SSL/TLS key material extraction simulation\n");
    printf("  - Key derivation for encryption/decryption\n");
    printf("  - Simulated decryption of TLS application data\n");
    printf("\nNote: This is a demonstration of TLS analysis concepts.\n");
    printf("      A full implementation would use eBPF for packet capture\n");
    printf("      and real SSL library hooking for key extraction.\n");
}

int main(int argc, char **argv) {
    int demo_mode = 0;
    int verbose = 0;
    int opt;
    
    while ((opt = getopt(argc, argv, "dvh")) != -1) {
        switch (opt) {
            case 'd':
                demo_mode = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    
    printf("TLS Traffic Analyzer Demo\n");
    printf("OpenSSL Version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("========================================\n\n");
    
    if (demo_mode) {
        demo_tls_analysis();
    } else {
        printf("Run with -d flag to see demonstration\n");
        printf("Run with -h flag for help\n");
    }
    
    return 0;
}