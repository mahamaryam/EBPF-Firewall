#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>   
#include <linux/if_vlan.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include <linux/netdevice.h>
#include <linux/route.h>

SEC("xdp")
int xdp_reverse_path_filtering(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    struct bpf_fib_lookup params = {};
    params.family = AF_INET;
    params.ipv4_src = ip->saddr;
    params.ipv4_dst = ip->daddr;
    params.ifindex = ctx->ingress_ifindex;

    int result = bpf_fib_lookup(ctx, &params, sizeof(params), 0); //routetablelookup
    if (result == BPF_FIB_LKUP_RET_SUCCESS)
    {
        if (params.ifindex != ctx->ingress_ifindex)
        {
            bpf_printk("spoofed ip.\n");       
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

