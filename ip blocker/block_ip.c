#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>  

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128); //max ip blocked
    __type(key, __u32); //ip
    __type(value, __u8); //whether or not ip is blocked
} blocked_ips SEC(".maps");


SEC("xdp")
int xdp_drop_ips(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if ((void *)(data+ sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth+1);
    if ((void *)(ip+1) > data_end)
        return XDP_PASS;

    __u32 decimal_ip = ip->saddr;  
    __u8 *ip_value = bpf_map_lookup_elem(&blocked_ips, &decimal_ip);
    
    if (ip_value) {
        if(*ip_value==0)
            return XDP_PASS;
        else if(*ip_value==1)
            return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

