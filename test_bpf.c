#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

SEC("xdp")
int tls_packet_capture(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count;
    
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    
    bpf_printk("Test BPF program called\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
