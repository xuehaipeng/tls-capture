#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define MAX_PACKET_SIZE 1500
#define MAX_FLOWS 1024
#define MAX_KEYS 256
#define TLS_RECORD_HEADER_SIZE 5
#define SSL_PORT 443

// TLS Record Types
#define TLS_CHANGE_CIPHER_SPEC 20
#define TLS_ALERT 21
#define TLS_HANDSHAKE 22
#define TLS_APPLICATION_DATA 23

// TLS Versions
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct tls_record_header {
    __u8 type;
    __u16 version;
    __u16 length;
} __attribute__((packed));

struct ssl_key_info {
    __u8 master_secret[48];
    __u8 client_random[32];
    __u8 server_random[32];
    __u16 cipher_suite;
    __u64 timestamp;
    __u32 valid;
};

struct packet_info {
    struct flow_key flow;
    __u32 seq_num;
    __u32 ack_num;
    __u16 payload_len;
    __u8 payload[MAX_PACKET_SIZE];
    __u64 timestamp;
};

struct flow_state {
    __u32 client_seq;
    __u32 server_seq;
    __u8 tls_established;
    __u8 key_extracted;
    __u64 last_seen;
};

#endif // COMMON_H