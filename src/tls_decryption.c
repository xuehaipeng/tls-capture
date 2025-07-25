#include "tls_capture.h"

// Function to derive TLS 1.2 traffic keys
int derive_tls12_traffic_keys(const uint8_t *master_secret,
                              const uint8_t *client_random,
                              const uint8_t *server_random,
                              uint8_t *client_write_key,
                              uint8_t *server_write_key,
                              uint8_t *client_write_iv,
                              uint8_t *server_write_iv) {
    if (!master_secret || !client_random || !server_random ||
        !client_write_key || !server_write_key ||
        !client_write_iv || !server_write_iv) {
        return -1;
    }
    
    // TLS 1.2 key derivation using PRF
    // This is a simplified implementation for demonstration
    
    uint8_t seed[64]; // client_random + server_random
    uint8_t key_block[128]; // Key block for encryption keys, MAC keys, and IVs
    
    // Create seed = client_random + server_random
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);
    
    // Derive key block using PRF (simplified)
    // For AES-128-GCM, we need:
    // - 16 bytes for client_write_key
    // - 16 bytes for server_write_key
    // - 4 bytes for client_write_IV
    // - 4 bytes for server_write_IV
    
    const char *label = "key expansion";
    
    // In a real implementation, we would use the actual TLS PRF
    // For demonstration, we'll generate pseudo-random values
    RAND_bytes(key_block, sizeof(key_block));
    
    // Extract keys (assuming client is the sender for this packet)
    memcpy(client_write_key, key_block, 16);      // client_write_key
    memcpy(server_write_key, key_block + 16, 16); // server_write_key
    memcpy(client_write_iv, key_block + 32, 4);  // client_write_IV
    memcpy(server_write_iv, key_block + 36, 4);  // server_write_IV
    
    return 0;
}

// Function to derive TLS 1.3 traffic keys
int derive_tls13_traffic_keys(const uint8_t *master_secret,
                              const uint8_t *client_random,
                              const uint8_t *server_random,
                              uint8_t *client_write_key,
                              uint8_t *server_write_key,
                              uint8_t *client_write_iv,
                              uint8_t *server_write_iv) {
    if (!master_secret || !client_random || !server_random ||
        !client_write_key || !server_write_key ||
        !client_write_iv || !server_write_iv) {
        return -1;
    }
    
    // TLS 1.3 key derivation using HKDF
    // This is a simplified implementation for demonstration
    
    uint8_t seed[64];
    
    // Create seed = client_random + server_random
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);
    
    // Derive keys using HMAC (simplified)
    unsigned int len;
    
    // Derive client_write_key
    HMAC(EVP_sha256(), master_secret, 48,
         seed, 64, client_write_key, &len);
    
    // Derive server_write_key
    seed[0] ^= 0xFF; // Modify seed slightly for different output
    HMAC(EVP_sha256(), master_secret, 48,
         seed, 64, server_write_key, &len);
    
    // Derive client_write_iv
    seed[0] ^= 0xAA; // Modify seed again
    HMAC(EVP_sha256(), master_secret, 48,
         seed, 64, client_write_iv, &len);
    
    // Derive server_write_iv
    seed[0] ^= 0x55; // Modify seed again
    HMAC(EVP_sha256(), master_secret, 48,
         seed, 64, server_write_iv, &len);
    
    // Truncate to appropriate sizes
    memset(client_write_key + 16, 0, 16); // AES-128 uses 16 bytes
    memset(server_write_key + 16, 0, 16); // AES-128 uses 16 bytes
    memset(client_write_iv + 12, 0, 4);   // GCM IV uses 12 bytes
    memset(server_write_iv + 12, 0, 4);   // GCM IV uses 12 bytes
    
    return 0;
}

// Function to decrypt AES-GCM TLS data
int decrypt_aes_gcm_tls(const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *key, const uint8_t *iv,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ret = -1;
    
    // Validate inputs
    if (!ciphertext || !key || !iv || !plaintext || !plaintext_len) {
        return -1;
    }
    
    // Need at least 16 bytes for GCM tag
    if (ciphertext_len < 16) {
        return -1;
    }
    
    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    // Initialize the decryption operation with AES-128-GCM
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        goto cleanup;
    }
    
    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        goto cleanup;
    }
    
    // Initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        goto cleanup;
    }
    
    // Set AAD if provided
    if (aad && aad_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            goto cleanup;
        }
    }
    
    // Provide the message to be decrypted (excluding the tag)
    size_t msg_len = ciphertext_len - 16;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, msg_len)) {
        goto cleanup;
    }
    *plaintext_len = len;
    
    // Set expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, 
                                 (void *)(ciphertext + msg_len))) {
        goto cleanup;
    }
    
    // Finalize the decryption
    int final_ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (final_ret > 0) {
        *plaintext_len += len;
        plaintext[*plaintext_len] = '\0'; // Null terminate
        ret = 0; // Success
    } else {
        ret = -1; // Decryption failed (authentication failed)
    }
    
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// Function to analyze a TLS packet with decryption
void analyze_tls_packet_with_decryption(const struct packet_info *pkt, const struct ssl_key_info *key) {
    if (!pkt || !key || !key->valid) {
        printf("❌ Invalid packet or key info\n");
        return;
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
        
        // Try to decrypt if this is application data
        if (tls_hdr.type == TLS_APPLICATION_DATA) {
            printf("🔍 TLS Application Data detected (potential HTTP content)\n");
            
            // Derive keys based on TLS version
            uint8_t client_write_key[32] = {0};
            uint8_t server_write_key[32] = {0};
            uint8_t client_write_iv[16] = {0};
            uint8_t server_write_iv[16] = {0};
            
            int ret;
            if (tls_hdr.version == TLS_VERSION_1_2) {
                ret = derive_tls12_traffic_keys(key->master_secret,
                                               key->client_random,
                                               key->server_random,
                                               client_write_key,
                                               server_write_key,
                                               client_write_iv,
                                               server_write_iv);
            } else if (tls_hdr.version == TLS_VERSION_1_3) {
                ret = derive_tls13_traffic_keys(key->master_secret,
                                               key->client_random,
                                               key->server_random,
                                               client_write_key,
                                               server_write_key,
                                               client_write_iv,
                                               server_write_iv);
            } else {
                printf("❌ Unsupported TLS version: 0x%04x\n", tls_hdr.version);
                return;
            }
            
            if (ret == 0) {
                // Use client_write_key for client-to-server traffic
                // Use server_write_key for server-to-client traffic
                uint8_t *dec_key = client_write_key;
                uint8_t *dec_iv = client_write_iv;
                
                // For simplicity, we'll assume client-to-server direction
                uint8_t plaintext[2048];
                size_t plaintext_len;
                
                // Decrypt the payload (excluding TLS record header)
                const uint8_t *encrypted_data = pkt->payload + TLS_RECORD_HEADER_SIZE;
                size_t encrypted_len = tls_hdr.length;
                
                if (encrypted_len > pkt->payload_len - TLS_RECORD_HEADER_SIZE) {
                    encrypted_len = pkt->payload_len - TLS_RECORD_HEADER_SIZE;
                }
                
                // Decrypt with AES-GCM
                ret = decrypt_aes_gcm_tls(encrypted_data, encrypted_len,
                                         dec_key, dec_iv,
                                         NULL, 0, // No AAD for simplicity
                                         plaintext, &plaintext_len);
                
                if (ret == 0) {
                    printf("🔓 Decrypted TLS data (%zu bytes):\n", plaintext_len);
                    
                    // Check if decrypted data looks like HTTP
                    if (plaintext_len > 4 && (strncmp((char*)plaintext, "GET ", 4) == 0 || 
                                             strncmp((char*)plaintext, "POST", 4) == 0 ||
                                             strncmp((char*)plaintext, "HTTP", 4) == 0 ||
                                             strncmp((char*)plaintext, "HEAD", 4) == 0 ||
                                             strncmp((char*)plaintext, "PUT ", 4) == 0 ||
                                             strncmp((char*)plaintext, "DELE", 4) == 0)) {
                        printf("🌐 HTTP Traffic Detected:\n");
                        printf("=== HTTP CONTENT ===\n");
                        // Print HTTP headers and body
                        for (size_t i = 0; i < plaintext_len && i < 1024; i++) {
                            putchar(plaintext[i]);
                            if (i > 4 && plaintext[i-3] == '\r' && plaintext[i-2] == '\n' &&
                                plaintext[i-1] == '\r' && plaintext[i] == '\n') {
                                // End of HTTP headers, add separator before body
                                printf("\n--- HTTP BODY ---\n");
                            }
                        }
                        if (plaintext_len > 1024) {
                            printf("\n... (truncated, %zu more bytes)\n", plaintext_len - 1024);
                        }
                        printf("\n=== END HTTP CONTENT ===\n");
                    } else {
                        // Not HTTP, show as generic decrypted data
                        print_decrypted_data((char*)plaintext, plaintext_len);
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
                printf("❌ Failed to derive TLS keys\n");
            }
        }
    }
}
