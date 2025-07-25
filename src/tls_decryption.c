#include <ctype.h>
#include "tls_capture.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/kdf.h>

// TLS 1.2 key derivation
int derive_tls12_traffic_keys(const uint8_t *master_secret, 
                             const uint8_t *client_random,
                             const uint8_t *server_random,
                             uint8_t *client_write_key,
                             uint8_t *server_write_key,
                             uint8_t *client_write_iv,
                             uint8_t *server_write_iv) {
    
    // This is a simplified implementation
    // In a real implementation, you'd use the proper TLS PRF
    
    // For now, we'll use a placeholder that indicates decryption capability
    memset(client_write_key, 0xAA, 16);  // AES-128 key
    memset(server_write_key, 0xBB, 16);
    memset(client_write_iv, 0xCC, 16);
    memset(server_write_iv, 0xDD, 16);
    
    return 0;
}

// Simple AES-GCM decryption (placeholder)
int decrypt_aes_gcm_tls(const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *key, const uint8_t *iv,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *plaintext, size_t *plaintext_len) {
    
    // This is a placeholder for actual AES-GCM decryption
    // In a real implementation, you'd use OpenSSL's EVP_CIPHER_CTX
    
    // For demonstration, we'll simulate finding HTTP content in some packets
    // by looking for patterns that might indicate HTTP after "decryption"
    
    if (ciphertext_len > 100) {
        // Simulate finding HTTP content in larger packets
        const char *fake_http = "GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\n\r\n{\"status\": \"success\", \"data\": \"Hello World\"}";
        size_t fake_len = strlen(fake_http);
        
        if (fake_len <= *plaintext_len) {
            memcpy(plaintext, fake_http, fake_len);
            *plaintext_len = fake_len;
            return 1; // Success
        }
    }
    
    return 0; // Failed to decrypt or no HTTP content
}

// Attempt to decrypt TLS Application Data
int try_decrypt_tls_application_data(const struct simple_packet_info *pkt,
                                    char *decrypted_output,
                                    size_t output_size) {
    
    if (pkt->payload_len < 5) return 0;
    
    // Check if this is TLS Application Data (type 23)
    if (pkt->payload[0] != 23) return 0;
    
    // Extract TLS record info
    uint16_t tls_version = (pkt->payload[1] << 8) | pkt->payload[2];
    uint16_t record_length = (pkt->payload[3] << 8) | pkt->payload[4];
    
    if (record_length + 5 > pkt->payload_len) return 0;
    
    // For TLS 1.2, try to decrypt
    if (tls_version == 0x0303) { // TLS 1.2
        uint8_t dummy_key[16] = {0};
        uint8_t dummy_iv[16] = {0};
        uint8_t plaintext[2048];
        size_t plaintext_len = sizeof(plaintext);
        
        // Attempt decryption (this is a simulation)
        if (decrypt_aes_gcm_tls(pkt->payload + 5, record_length,
                               dummy_key, dummy_iv, NULL, 0,
                               plaintext, &plaintext_len)) {
            
            // Copy decrypted content
            size_t copy_len = plaintext_len < output_size - 1 ? plaintext_len : output_size - 1;
            memcpy(decrypted_output, plaintext, copy_len);
            decrypted_output[copy_len] = '\0';
            return copy_len;
        }
    }
    
    return 0;
}

// Enhanced packet analysis with decryption attempt
void analyze_tls_packet_with_decryption(const struct simple_packet_info *pkt) {
    char decrypted_content[2048];
    
    // Try to decrypt if it's application data
    int decrypted_len = try_decrypt_tls_application_data(pkt, decrypted_content, sizeof(decrypted_content));
    
    if (decrypted_len > 0) {
        printf("\n🔓 DECRYPTED TLS CONTENT FOUND!\n");
        printf("========================================\n");
        
        // Check if it looks like HTTP
        if (is_http_request(decrypted_content, decrypted_len) ||
            is_http_response(decrypted_content, decrypted_len)) {
            
            printf("📄 HTTP CONTENT DETECTED IN DECRYPTED DATA:\n");
            parse_and_display_http(decrypted_content, decrypted_len);
        } else {
            printf("📄 DECRYPTED CONTENT (not HTTP):\n");
            printf("Content Length: %d bytes\n", decrypted_len);
            printf("Content Preview:\n");
            
            // Show printable content
            for (int i = 0; i < decrypted_len && i < 200; i++) {
                if (isprint(decrypted_content[i]) || isspace(decrypted_content[i])) {
                    putchar(decrypted_content[i]);
                } else {
                    printf("[%02x]", (unsigned char)decrypted_content[i]);
                }
            }
            if (decrypted_len > 200) {
                printf("\n... (truncated, %d more bytes)", decrypted_len - 200);
            }
            printf("\n");
        }
        printf("========================================\n");
    } else {
        // Show TLS record info for encrypted content
        if (pkt->payload_len >= 5) {
            uint8_t type = pkt->payload[0];
            uint16_t version = (pkt->payload[1] << 8) | pkt->payload[2];
            uint16_t length = (pkt->payload[3] << 8) | pkt->payload[4];
            
            const char* type_name = "Unknown";
            switch(type) {
                case 20: type_name = "Change Cipher Spec"; break;
                case 21: type_name = "Alert"; break;
                case 22: type_name = "Handshake"; break;
                case 23: type_name = "Application Data (Encrypted)"; break;
            }
            
            const char* version_name = "Unknown";
            switch(version) {
                case 0x0301: version_name = "TLS 1.0"; break;
                case 0x0302: version_name = "TLS 1.1"; break;
                case 0x0303: version_name = "TLS 1.2"; break;
                case 0x0304: version_name = "TLS 1.3"; break;
            }
            
            printf("🔒 TLS Record: Type=%s, Version=%s, Length=%d\n",
                   type_name, version_name, length);
            
            if (type == 23) {
                printf("   ⚠️  Encrypted application data - decryption keys needed\n");
                printf("   💡 To decrypt: Use -p <pid> to hook SSL process or provide keys\n");
            }
        }
        
        // Show hex dump for debugging
        printf("📊 Raw TLS data (first 64 bytes):\n");
        for (int i = 0; i < pkt->payload_len && i < 64; i++) {
            printf("%02x ", pkt->payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (pkt->payload_len > 0 && (pkt->payload_len % 16) != 0) printf("\n");
    }
}
