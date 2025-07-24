#include "tls_capture.h"

int parse_tls_record(const __u8 *data, size_t len, struct tls_record_header *header) {
    if (!data || !header || len < TLS_RECORD_HEADER_SIZE) {
        return -1;
    }
    
    // Parse TLS record header
    header->type = data[0];
    header->version = (data[1] << 8) | data[2];
    header->length = (data[3] << 8) | data[4];
    
    // Validate TLS record type
    if (header->type < TLS_CHANGE_CIPHER_SPEC || header->type > TLS_APPLICATION_DATA) {
        return -1;
    }
    
    // Validate TLS version
    if (header->version != TLS_VERSION_1_2 && header->version != TLS_VERSION_1_3) {
        return -1;
    }
    
    // Validate length
    if (header->length > len - TLS_RECORD_HEADER_SIZE) {
        return -1;
    }
    
    return 0;
}

void print_decrypted_data(const char *data, size_t len) {
    if (!data || len == 0) {
        return;
    }
    
    printf("=== DECRYPTED CONTENT ===\n");
    
    // Try to detect if it's HTTP data
    if (len > 4 && (strncmp(data, "GET ", 4) == 0 || 
                    strncmp(data, "POST", 4) == 0 ||
                    strncmp(data, "HTTP", 4) == 0)) {
        printf("HTTP Traffic Detected:\n");
        printf("%.*s\n", (int)len, data);
    } else {
        // Print as hex and ASCII
        printf("Raw Data (%zu bytes):\n", len);
        
        for (size_t i = 0; i < len; i += 16) {
            // Print hex
            printf("%08zx: ", i);
            for (size_t j = 0; j < 16 && i + j < len; j++) {
                printf("%02x ", (unsigned char)data[i + j]);
            }
            
            // Pad if necessary
            for (size_t j = len - i; j < 16; j++) {
                printf("   ");
            }
            
            // Print ASCII
            printf(" |");
            for (size_t j = 0; j < 16 && i + j < len; j++) {
                char c = data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("|\n");
        }
    }
    
    printf("=== END DECRYPTED CONTENT ===\n");
}

const char* get_tls_record_type_name(int type) {
    switch (type) {
        case TLS_CHANGE_CIPHER_SPEC:
            return "Change Cipher Spec";
        case TLS_ALERT:
            return "Alert";
        case TLS_HANDSHAKE:
            return "Handshake";
        case TLS_APPLICATION_DATA:
            return "Application Data";
        default:
            return "Unknown";
    }
}

const char* get_tls_version_name(int version) {
    switch (version) {
        case TLS_VERSION_1_2:
            return "TLS 1.2";
        case TLS_VERSION_1_3:
            return "TLS 1.3";
        default:
            return "Unknown";
    }
}

void print_tls_record_info(const struct tls_record_header *header) {
    if (!header) {
        return;
    }
    
    printf("TLS Record: Type=%s, Version=%s, Length=%d\n",
           get_tls_record_type_name(header->type),
           get_tls_version_name(header->version),
           header->length);
}

void print_flow_info(const struct flow_key *flow) {
    if (!flow) {
        return;
    }
    
    struct in_addr src_addr = { .s_addr = flow->src_ip };
    struct in_addr dst_addr = { .s_addr = flow->dst_ip };
    
    printf("Flow: %s:%d -> %s:%d (proto=%d)\n",
           inet_ntoa(src_addr), ntohs(flow->src_port),
           inet_ntoa(dst_addr), ntohs(flow->dst_port),
           flow->protocol);
}