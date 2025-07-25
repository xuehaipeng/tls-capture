#include "tls_capture.h"

// TLS Pseudo-Random Function (PRF) for key derivation
static int tls12_prf(const __u8 *secret, int secret_len,
                     const __u8 *label, int label_len,
                     const __u8 *seed, int seed_len,
                     __u8 *out, int out_len) {
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = EVP_sha256();
    __u8 *a = NULL, *tmp = NULL;
    int a_len, tmp_len, chunk;
    int ret = -1;
    
    if (!secret || !label || !seed || !out) {
        return -1;
    }
    
    a_len = EVP_MD_size(md);
    tmp_len = a_len + label_len + seed_len;
    
    a = malloc(a_len);
    tmp = malloc(tmp_len);
    
    if (!a || !tmp) {
        goto cleanup;
    }
    
    // A(0) = seed
    memcpy(tmp + label_len, seed, seed_len);
    memcpy(tmp, label, label_len);
    
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        goto cleanup;
    }
    
    // Calculate A(1)
    if (HMAC(md, secret, secret_len, tmp, label_len + seed_len, a, NULL) <= 0) {
        goto cleanup;
    }
    
    while (out_len > 0) {
        // Calculate P_hash[i] = HMAC_hash(secret, A(i) + seed)
        memcpy(tmp, a, a_len);
        memcpy(tmp + a_len, label, label_len);
        memcpy(tmp + a_len + label_len, seed, seed_len);
        
        if (HMAC(md, secret, secret_len, tmp, tmp_len, tmp, NULL) <= 0) {
            goto cleanup;
        }
        
        chunk = (out_len < a_len) ? out_len : a_len;
        memcpy(out, tmp, chunk);
        out += chunk;
        out_len -= chunk;
        
        if (out_len > 0) {
            // Calculate A(i+1) = HMAC_hash(secret, A(i))
            if (HMAC(md, secret, secret_len, a, a_len, tmp, NULL) <= 0) {
                goto cleanup;
            }
            memcpy(a, tmp, a_len);
        }
    }
    
    ret = 0;
    
cleanup:
    if (ctx) EVP_MD_CTX_free(ctx);
    if (a) free(a);
    if (tmp) free(tmp);
    
    return ret;
}

int derive_tls12_keys(const struct ssl_key_info *key_info, __u8 *enc_key, __u8 *mac_key, __u8 *iv) {
    if (!key_info || !enc_key || !mac_key || !iv) {
        return -1;
    }
    
    // TLS 1.2 key derivation using PRF
    // This is a more accurate implementation of the TLS 1.2 key derivation
    
    __u8 seed[64]; // client_random + server_random
    __u8 key_block[128]; // Key block for encryption keys, MAC keys, and IVs
    
    // Create seed = client_random + server_random
    memcpy(seed, key_info->client_random, 32);
    memcpy(seed + 32, key_info->server_random, 32);
    
    // Derive key block using PRF
    // For AES-128-GCM, we need:
    // - 16 bytes for client_write_key
    // - 16 bytes for server_write_key
    // - 4 bytes for client_write_IV
    // - 4 bytes for server_write_IV
    const char *label = "key expansion";
    
    if (tls12_prf(key_info->master_secret, 48,
                  (const __u8 *)label, strlen(label),
                  seed, 64,
                  key_block, 64) < 0) {
        return -1;
    }
    
    // Extract keys (assuming client is the sender for this packet)
    memcpy(enc_key, key_block, 16);      // client_write_key
    memcpy(mac_key, key_block + 16, 16); // client_write_MAC_key
    memcpy(iv, key_block + 32, 4);       // client_write_IV
    
    return 0;
}

int derive_tls13_keys(const struct ssl_key_info *key_info, __u8 *enc_key, __u8 *iv) {
    // For TLS 1.3, we'll implement a simplified version
    // Real implementation would use HKDF
    
    if (!key_info || !enc_key || !iv) {
        return -1;
    }
    
    // Use a simplified approach for demonstration
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    // Derive keys using HMAC
    unsigned int len;
    __u8 seed[64];
    
    // Create seed = client_random + server_random
    memcpy(seed, key_info->client_random, 32);
    memcpy(seed + 32, key_info->server_random, 32);
    
    // Derive encryption key
    HMAC(EVP_sha256(), key_info->master_secret, 48,
         seed, 64, enc_key, &len);
    
    // Derive IV
    seed[0] ^= 0xFF; // Modify seed slightly for different output
    HMAC(EVP_sha256(), key_info->master_secret, 48,
         seed, 64, iv, &len);
    
    EVP_MD_CTX_free(ctx);
    
    // Truncate to appropriate sizes
    memset(enc_key + 16, 0, 16); // AES-128 uses 16 bytes
    memset(iv + 12, 0, 4);       // GCM IV uses 12 bytes
    
    return 0;
}

int decrypt_aes_gcm(const __u8 *ciphertext, size_t ciphertext_len,
                    const __u8 *key, const __u8 *iv, __u8 *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len, ret = -1;
    
    // Validate inputs
    if (!ciphertext || !key || !iv || !plaintext) {
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
    
    // Provide the message to be decrypted (excluding the tag)
    size_t msg_len = ciphertext_len - 16;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, msg_len)) {
        goto cleanup;
    }
    plaintext_len = len;
    
    // Set expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, 
                                 (void *)(ciphertext + msg_len))) {
        goto cleanup;
    }
    
    // Finalize the decryption
    int final_ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (final_ret > 0) {
        plaintext_len += len;
        plaintext[plaintext_len] = '\0'; // Null terminate
        ret = plaintext_len;
    } else {
        ret = -1; // Decryption failed (authentication failed)
    }
    
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decrypt_tls_data(const struct packet_info *pkt, const struct ssl_key_info *key_info,
                     char *output, size_t output_size) {
    if (!pkt || !key_info || !output || !key_info->valid) {
        return -1;
    }
    
    // Parse TLS record header
    if (pkt->payload_len < TLS_RECORD_HEADER_SIZE) {
        return -1;
    }
    
    struct tls_record_header tls_hdr;
    if (parse_tls_record(pkt->payload, pkt->payload_len, &tls_hdr) < 0) {
        return -1;
    }
    
    // Only decrypt application data
    if (tls_hdr.type != TLS_APPLICATION_DATA) {
        return -1;
    }
    
    __u8 enc_key[32] = {0};
    __u8 mac_key[32] = {0};
    __u8 iv[16] = {0};
    
    // Derive keys based on TLS version
    if (tls_hdr.version == TLS_VERSION_1_2) {
        if (derive_tls12_keys(key_info, enc_key, mac_key, iv) < 0) {
            printf("Failed to derive TLS 1.2 keys\n");
            return -1;
        }
        // For TLS 1.2, IV is often derived from sequence number
        // Combine the derived IV with sequence number for GCM
        __u64 seq_num_be = htobe64(pkt->seq_num);
        memcpy(iv + 4, &seq_num_be, 8);
    } else if (tls_hdr.version == TLS_VERSION_1_3) {
        if (derive_tls13_keys(key_info, enc_key, iv) < 0) {
            printf("Failed to derive TLS 1.3 keys\n");
            return -1;
        }
        // For TLS 1.3, IV is combined with sequence number
        __u64 seq_num_be = htobe64(pkt->seq_num);
        for (int i = 0; i < 8; i++) {
            iv[4 + i] ^= ((seq_num_be >> (8 * (7 - i))) & 0xFF);
        }
    } else {
        printf("Unsupported TLS version: 0x%04x\n", tls_hdr.version);
        return -1;
    }
    
    // Decrypt the payload
    const __u8 *encrypted_data = pkt->payload + TLS_RECORD_HEADER_SIZE;
    size_t encrypted_len = tls_hdr.length;
    
    if (encrypted_len > pkt->payload_len - TLS_RECORD_HEADER_SIZE) {
        encrypted_len = pkt->payload_len - TLS_RECORD_HEADER_SIZE;
    }
    
    // Ensure we have enough space for the tag
    if (encrypted_len < 16) {
        printf("Encrypted data too short for GCM tag\n");
        return -1;
    }
    
    int decrypted_len = decrypt_aes_gcm(encrypted_data, encrypted_len,
                                        enc_key, iv, (__u8 *)output);
    
    if (decrypted_len > 0 && decrypted_len < (int)output_size) {
        output[decrypted_len] = '\0';
        return decrypted_len;
    } else if (decrypted_len < 0) {
        printf("Decryption failed (possibly wrong keys or corrupted data)\n");
        return -1;
    }
    
    return -1;
}
