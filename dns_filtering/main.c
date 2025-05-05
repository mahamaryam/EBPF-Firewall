#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT 53
#define MAX_DOMAIN_LEN 256

char _license[] SEC("license") = "GPL";

// eBPF map to hold blocked domain (e.g., "bad.com")
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[MAX_DOMAIN_LEN]);
    __type(value, __u8); // value unused, just marker
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_domains SEC(".maps");

static __always_inline int parse_qname(void *qname_base, void *data_end, char *out, int max_len)
{
    int i = 0;
    while (qname_base < data_end)
    {
        if (qname_base + 1 > data_end)
            return -1;

        __u8 len = *(__u8 *)qname_base++;
        if (!len || len >= MAX_DOMAIN_LEN)
            break;

        if (i != 0 && i < max_len - 1)
            out[i++] = '.';

        if (qname_base + 1 + len > data_end)
            return -1;
        if (i + len >= max_len)
            return -1;

        __u8 j = len;
        while (j--)
        {
            if ((qname_base + 1 > data_end) || (i + 2 >= max_len))   // I don't know why (i+1 >= max_len) wasn't working :)
                return -1;
            out[i++] = *(char *)qname_base++;
        }
    }

    if (i + 1 >= max_len)
        return -1;
    out[i] = '\0';

    // bpf_printk("Domain Name : %s", out);
    return 0;
}

/// @tchook {"ifindex":3, "attach_point":"BPF_TC_EGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int dns_filter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // IPv4 only
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // UDP header
    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(udp->dest) != DNS_PORT)
        return TC_ACT_OK;

    void *qname_base = (void *)udp + sizeof(*udp) + 12; // DNS header is 12 bytes

    char domain[MAX_DOMAIN_LEN] = {};
    if (parse_qname(qname_base, data_end, domain, sizeof(domain)) < 0)
        return TC_ACT_OK;

    // Check against blocklist
    __u8 *blocked = bpf_map_lookup_elem(&blocked_domains, &domain);
    if (blocked)
    {
        bpf_printk("Blocked DNS query for: %s\n", domain);
        return TC_ACT_SHOT; // Drop packet
    }

    return TC_ACT_OK;
}
