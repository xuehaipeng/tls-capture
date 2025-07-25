#ifndef SIMPLE_BPF_TYPES_H
#define SIMPLE_BPF_TYPES_H

// Simplified types for BPF compilation
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

// Network protocol constants
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// Ethernet header
struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
} __attribute__((packed));

// IP header
struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

// TCP header
struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 res1:4;
    __u16 doff:4;
    __u16 fin:1;
    __u16 syn:1;
    __u16 rst:1;
    __u16 psh:1;
    __u16 ack:1;
    __u16 urg:1;
    __u16 ece:1;
    __u16 cwr:1;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

// XDP action codes
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

// XDP metadata
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#endif // SIMPLE_BPF_TYPES_H