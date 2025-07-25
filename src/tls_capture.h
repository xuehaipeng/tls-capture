#ifndef TLS_CAPTURE_H
#define TLS_CAPTURE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <pthread.h>
#include "common.h"

// Function declarations
int load_bpf_program(const char *filename);
int setup_ssl_hooks(void);
void cleanup_ssl_hooks(void);
int decrypt_tls_data(const struct packet_info *pkt, const struct ssl_key_info *key, 
                     char *output, size_t output_size);
int parse_tls_record(const __u8 *data, size_t len, struct tls_record_header *header);
void print_decrypted_data(const char *data, size_t len);
const char* get_tls_record_type_name(int type);
const char* get_tls_version_name(int version);
void cleanup_and_exit(int sig);

// Global variables
extern volatile int running;
extern int bpf_prog_fd;
extern int flow_map_fd;
extern int key_map_fd;
extern int packet_map_fd;

// SSL hooking functions
int hook_ssl_functions(void);
void extract_ssl_keys(SSL *ssl, struct ssl_key_info *key_info);

// Crypto utilities
int derive_tls12_keys(const struct ssl_key_info *key_info, __u8 *enc_key, __u8 *mac_key, __u8 *iv);
int derive_tls13_keys(const struct ssl_key_info *key_info, __u8 *enc_key, __u8 *iv);
int decrypt_aes_gcm(const __u8 *ciphertext, size_t ciphertext_len,
                    const __u8 *key, const __u8 *iv, __u8 *plaintext);

#endif // TLS_CAPTURE_H
