#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8);  //protocol number
    __type(value, __u8); //1 = blocked 0 unblocked, no 0 needed. dummy shit.
} protocol_blocker SEC(".maps");

SEC("xdp")
int xdp_protocol_block(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;
    
    __u8 protocol = iph->protocol;
    
    __u8 *blocked = bpf_map_lookup_elem(&protocol_blocker, &protocol);
    if (blocked)
    {  bpf_printk("dropping protocol %d\n",protocol);
        return XDP_DROP;  
        }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
