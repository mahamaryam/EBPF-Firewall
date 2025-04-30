//problem: can't pin maps.
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
} ip_blocklist SEC(".maps");

SEC("xdp")
int ip_range_blocking(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
//routine things.
    if ((void *)(data + sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) 
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    __u32 decimal_ip = bpf_ntohl(ip->saddr);

#pragma unroll
for (int i = 0; i < 50; i++) {
    struct ip_mask *ip_get;
    int index = i; 
    //separate variable 
    /*Clang must know the loop bounds and index are constant. If you use &i directly in bpf_map_lookup_elem, it may prevent unrolling because &i is on the stack and changes each iteration.
    Instead, assign the loop index i to a fixed scalar variable (index) on each iteration. This is a known workaround for unrolling in BPF.And in each of those cases, the index can be 
    evaluated as a known immediate value, allowing the verifier to track the pointer safety and avoid rejecting it.
*/
    ip_get = bpf_map_lookup_elem(&ip_blocklist, &index); //add null case.
    if(!ip_get) return XDP_PASS;
    if ((decimal_ip & ip_get->mask) == (ip_get->ip & ip_get->mask)) 
        return XDP_DROP;
}
//another option to xor the ip->saddr with the ip in my map and then and with the mask to see if all zeroes, then drop.
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
