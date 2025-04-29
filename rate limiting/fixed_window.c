#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
//enter ip in reverse. 192.168.1.10---> 10 1 168 192
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, __u8); //can store up to the user defined number... of packets allowed per 10seconds.
} fixed_window_per_ip SEC(".maps");

//second struct for holding the current packets. cmp with fixed_window_per_ip.value to see if ==. have ip as key.
struct 
{
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries,2048);
__type(key, __u32); //ip
__type(value, __u8); //current packets per 10s.
} current_packets SEC(".maps");

SEC("xdp")
int fixed_window_rate(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;
    
    //ip conversions.
    __u32 ip_addr = bpf_ntohl(iph->saddr);
    __u8 *blocked = bpf_map_lookup_elem(&fixed_window_per_ip, &ip_addr); //get fixed ip limit
    __u8 *curr = bpf_map_lookup_elem(&current_packets, &ip_addr);//get current ip packets 
    
    if (blocked) { //ip exists in the map and hard limit for it has been set.

        if (curr) 
        { //ip also has a current number of packets sent.
            
            if (*blocked <= *curr) 
            {
                bpf_printk("dropping packets from IP: %u", ip_addr);
                return XDP_DROP;
            } 
            else 
            {
                bpf_printk("increment packet count for IP: %u ", ip_addr);
                (*curr)++;
            }
        } 
        else {
            //first pakcet for ip is here.
            __u8 val = 1;
            bpf_map_update_elem(&current_packets, &ip_addr, &val, BPF_ANY);
            bpf_printk("first packet IP: %u", ip_addr);
        }
    } 
    else { //block == NULL, meaning the ip is new to use.
        bpf_printk("ip adding to map: %u", ip_addr);
        __u8 val = 1;  //curr=1
        __u8 lim = 100; //default limit.
        bpf_map_update_elem(&fixed_window_per_ip, &ip_addr, &lim, BPF_ANY);
        bpf_map_update_elem(&current_packets, &ip_addr, &val, BPF_ANY);
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

