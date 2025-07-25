#include "tls_capture.h"
#include <ctype.h>

// HTTP parsing functions
int is_http_request(const char *data, size_t len) {
    if (len < 4) return 0;
    return (strncmp(data, "GET ", 4) == 0 ||
            strncmp(data, "POST", 4) == 0 ||
            strncmp(data, "PUT ", 4) == 0 ||
            strncmp(data, "HEAD", 4) == 0 ||
            strncmp(data, "DELE", 4) == 0 ||
            strncmp(data, "OPTI", 4) == 0 ||
            strncmp(data, "PATC", 4) == 0);
}

int is_http_response(const char *data, size_t len) {
    if (len < 8) return 0;
    return strncmp(data, "HTTP/", 5) == 0;
}

void parse_and_display_http(const char *data, size_t len) {
    if (!data || len == 0) return;
    
    printf("\n=== HTTP CONTENT DETECTED ===\n");
    
    // Find end of headers (double CRLF)
    const char *header_end = strstr(data, "\r\n\r\n");
    if (!header_end) {
        header_end = strstr(data, "\n\n");
        if (header_end) header_end += 2;
    } else {
        header_end += 4;
    }
    
    // Display headers
    if (header_end) {
        size_t header_len = header_end - data;
        printf("HTTP Headers:\n");
        printf("----------------------------------------\n");
        
        // Print headers line by line
        const char *line_start = data;
        for (size_t i = 0; i < header_len; i++) {
            if (data[i] == '\n') {
                // Print the line
                size_t line_len = &data[i] - line_start;
                if (line_len > 0 && data[i-1] == '\r') line_len--;
                printf("%.*s\n", (int)line_len, line_start);
                line_start = &data[i + 1];
            }
        }
        
        // Display body if present
        const char *body = header_end;
        size_t body_len = len - (body - data);
        
        if (body_len > 0) {
            printf("\nHTTP Body (%zu bytes):\n", body_len);
            printf("----------------------------------------\n");
            
            // Check if body is text-based
            int is_text = 1;
            for (size_t i = 0; i < body_len && i < 100; i++) {
                if (!isprint(body[i]) && !isspace(body[i])) {
                    is_text = 0;
                    break;
                }
            }
            
            if (is_text) {
                // Display as text (limit to reasonable size)
                size_t display_len = body_len > 1000 ? 1000 : body_len;
                printf("%.*s", (int)display_len, body);
                if (body_len > 1000) {
                    printf("\n... (truncated, %zu more bytes)", body_len - 1000);
                }
                printf("\n");
            } else {
                printf("[Binary content - %zu bytes]\n", body_len);
                // Show hex dump of first 64 bytes
                printf("First 64 bytes (hex):\n");
                for (size_t i = 0; i < body_len && i < 64; i++) {
                    printf("%02x ", (unsigned char)body[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                if (body_len > 0 && (body_len % 16) != 0) printf("\n");
            }
        }
    } else {
        // No clear header/body separation, just display as is
        printf("Raw HTTP Data:\n");
        printf("----------------------------------------\n");
        size_t display_len = len > 500 ? 500 : len;
        printf("%.*s", (int)display_len, data);
        if (len > 500) {
            printf("\n... (truncated, %zu more bytes)", len - 500);
        }
        printf("\n");
    }
    
    printf("=== END HTTP CONTENT ===\n\n");
}

int try_decrypt_and_parse_http(const struct packet_info *pkt, const struct ssl_key_info *key) {
    // This is a placeholder for actual TLS decryption
    // For now, we'll just check if the raw payload looks like HTTP
    
    if (pkt->payload_len < 4) return 0;
    
    // Check if payload looks like plaintext HTTP (for testing)
    if (is_http_request((char*)pkt->payload, pkt->payload_len) ||
        is_http_response((char*)pkt->payload, pkt->payload_len)) {
        parse_and_display_http((char*)pkt->payload, pkt->payload_len);
        return 1;
    }
    
    return 0;
}
