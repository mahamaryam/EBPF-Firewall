#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h> 

struct ip_mask {
    __u32 ip;
    __u32 mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50);
    __type(key, int);
    __type(value, struct ip_mask);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_blocklist SEC(".maps");

SEC("xdp")
int ip_range_blocking(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet header validation
    if ((void *)(data + sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) 
        return XDP_PASS;
    
    // IP header validation
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Convert source IP from network to host byte order
    __u32 decimal_ip = bpf_ntohl(ip->saddr);
    
    // Initialize to check if we've found a match
    int match_found = 0;
    
    // Lookup in the blocklist
    #pragma unroll
    for (int i = 0; i < 50; i++) {
        int index = i;
        struct ip_mask *ip_get = bpf_map_lookup_elem(&ip_blocklist, &index);
        
        // Break early if we hit an empty entry
        if (!ip_get)
            break;
        
        // Check if IP matches the subnet
        if ((decimal_ip & ip_get->mask) == (ip_get->ip & ip_get->mask)) {
            match_found = 1;
            break;
        }
    }
    
    if (match_found) {
        bpf_printk("Blocked IP: %u.%u.%u\n", 
                  (decimal_ip >> 24) & 0xFF,
                  (decimal_ip >> 16) & 0xFF,
                  (decimal_ip >> 8) & 0xFF);
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
