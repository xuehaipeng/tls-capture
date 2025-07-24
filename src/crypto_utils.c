#include "tls_capture.h"

int derive_tls12_keys(const struct ssl_key_info *key_info, __u8 *enc_key, __u8 *mac_key) {
    if (!key_info || !enc_key || !mac_key) {
        return -1;
    }
    
    // TLS 1.2 key derivation using HMAC-based key derivation
    // This is a simplified version - real implementation would be more complex
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    // Use master secret to derive encryption and MAC keys
    // In real TLS 1.2, this involves PRF (Pseudo-Random Function)
    
    // For demonstration, we'll use a simple HMAC approach
    unsigned int len;
    HMAC(EVP_sha256(), key_info->master_secret, sizeof(key_info->master_secret),
         key_info->client_random, sizeof(key_info->client_random),
         enc_key, &len);
    
    HMAC(EVP_sha256(), key_info->master_secret, sizeof(key_info->master_secret),
         key_info->server_random, sizeof(key_info->server_random),
         mac_key, &len);
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

int derive_tls13_keys(const struct ssl_key_info *key_info, __u8 *enc_key, __u8 *iv) {
    // For MVP, we'll skip TLS 1.3 key derivation as it's complex
    // and requires more sophisticated HKDF implementation
    
    if (!key_info || !enc_key || !iv) {
        return -1;
    }
    
    // Just copy dummy values for demonstration
    memset(enc_key, 0, 16); // AES-128 key
    memset(iv, 0, 12);      // GCM IV
    
    return 0;
}

int decrypt_aes_gcm(const __u8 *ciphertext, size_t ciphertext_len,
                    const __u8 *key, const __u8 *iv, __u8 *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret = -1;
    
    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
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
    
    // Provide the message to be decrypted
    if (ciphertext_len < 16) { // Need at least 16 bytes for GCM tag
        goto cleanup;
    }
    
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
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret > 0) {
        plaintext_len += len;
        ret = plaintext_len;
    } else {
        ret = -1;
    }
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
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
    
    __u8 enc_key[32];
    __u8 mac_key[32];
    __u8 iv[16];
    
    // Derive keys based on TLS version
    if (tls_hdr.version == TLS_VERSION_1_2) {
        if (derive_tls12_keys(key_info, enc_key, mac_key) < 0) {
            return -1;
        }
        // For TLS 1.2, IV is often derived from sequence number
        memcpy(iv, &pkt->seq_num, 4);
        memset(iv + 4, 0, 12);
    } else if (tls_hdr.version == TLS_VERSION_1_3) {
        if (derive_tls13_keys(key_info, enc_key, iv) < 0) {
            return -1;
        }
    } else {
        return -1;
    }
    
    // Decrypt the payload
    const __u8 *encrypted_data = pkt->payload + TLS_RECORD_HEADER_SIZE;
    size_t encrypted_len = tls_hdr.length;
    
    if (encrypted_len > pkt->payload_len - TLS_RECORD_HEADER_SIZE) {
        encrypted_len = pkt->payload_len - TLS_RECORD_HEADER_SIZE;
    }
    
    int decrypted_len = decrypt_aes_gcm(encrypted_data, encrypted_len,
                                        enc_key, iv, (__u8 *)output);
    
    if (decrypted_len > 0 && decrypted_len < (int)output_size) {
        output[decrypted_len] = '\0';
    }
    
    return decrypted_len;
}
