#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//blocked ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  //port number
    __type(value, __u8); //0 or 1.
} port_blocker SEC(".maps");

SEC("xdp")
int xdp_port_block(struct xdp_md *ctx)
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
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    __u16 dst_port = 0;
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);
        if ((void *)tcph + sizeof(*tcph) > data_end)
            return XDP_PASS;        
        dst_port = bpf_ntohs(tcph->dest);
    }
    else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(*iph);
        if ((void *)udph + sizeof(*udph) > data_end)
            return XDP_PASS;  
        dst_port = bpf_ntohs(udph->dest);
    }
    
    //lookup
    __u8 *blocked = bpf_map_lookup_elem(&port_blocker, &dst_port);
    if (blocked)
        return XDP_DROP;  
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
