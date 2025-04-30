#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h> //IPPROTO_TCP
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "conn_tab.h"

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *cursor = data + sizeof(*eth);

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))
    {
        if ((void *)(cursor + sizeof(struct vlan_hdr)) > data_end)
            return XDP_PASS;
        struct vlan_hdr *vhdr = cursor;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        cursor += sizeof(struct vlan_hdr);
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct conn_key key = {};

    key.src_ip = (ip->saddr > ip->daddr) ? ip->saddr : ip->daddr,
    key.dst_ip = (ip->saddr < ip->daddr) ? ip->daddr : ip->saddr,
    key.src_port = (tcp->source > tcp->dest) ? tcp->source : tcp->dest,
    key.dst_port = (tcp->source < tcp->dest) ? tcp->source : tcp->dest,
    key.protocol = ip->protocol,

    bpf_printk(FORMAT, bpf_ntohs(key.src_port), bpf_ntohs(key.dst_port), tcp->syn, tcp->ack, tcp->fin, tcp->rst);

    struct conn_value *conn = bpf_map_lookup_elem(&conn_table, &key);
    __u64 now = bpf_ktime_get_ns();

    if (!conn)
    {
        if (tcp->syn && !tcp->ack)
        {
            struct conn_value new_conn = {};
            new_conn.state = BPF_TCP_SYN_RECV;
            new_conn.last_seen = now;
            bpf_map_update_elem(&conn_table, &key, &new_conn, BPF_ANY);
            bpf_printk("INGRESS [*] SYN received");
        }
        else
        {
            bpf_printk("INGRESS [*] New Conection ---> Not SYN ---> Dropping");
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    // bpf_spin_lock(&conn->lock);

    if ((now - conn->last_seen) > TIMEOUT_NS)
    {
        // bpf_spin_unlock(&conn->lock);
        if (!bpf_map_delete_elem(&conn_table, &key))
        {
            bpf_printk("INGRESS [*] Timeout Issue ----> Dropping");
        }
        else
        {
            bpf_printk("Timeout Issue ---> connection not deleted");
        }
        return XDP_DROP;
    }

    switch (conn->state)
    {
    case BPF_TCP_SYN_SENT:

        // meaning now ack is here for case 1.
        bpf_printk("INGRESS [*] BPF_TCP_SYN_SENT CASE");
        if (!tcp->syn && tcp->ack)
        {
            bpf_printk("INGRESS [*] ACK received");
            conn->state = BPF_TCP_ESTABLISHED;
        }
        // case 2 for when i initiated connection by sending syn and now i am getting synack.
        else if (tcp->syn && tcp->ack)
        {
            bpf_printk("INGRESS [*] SYN-ACK received");
            conn->state = BPF_TCP_SYN_RECV;
        }
        else if (tcp->rst) // Connection refused by server
        {
            bpf_printk("INGRESS: [*] RST received ---> Terminating Connection");
            conn->state = BPF_TCP_CLOSE;
            bpf_map_delete_elem(&conn_table, &key);
        }
        else
        {
            bpf_printk("INGRESS: [*] Unkown ---> Debug it");
            goto drop_unlock;
        }
        break;

    case BPF_TCP_SYN_RECV:
        bpf_printk("INGRESS [*] BPF_TCP_SYN_RECV CASE");
        if (tcp->ack && !tcp->syn)
        {
            bpf_printk("INGRESS [*] ACK received");
            conn->state = BPF_TCP_ESTABLISHED;
        }
        else
        {
            bpf_printk("INGRESS: [*] Unknown ---> Debug it");
            goto drop_unlock;
        }
        break;

    case BPF_TCP_ESTABLISHED:
        bpf_printk("INGRESS [*] BPF_TCP_ESTABLISHED CASE");
        if (tcp->fin)
        {
            bpf_printk("INGRESS [*] FIN received");
            conn->state = BPF_TCP_FIN_WAIT1;
        }
        else if (tcp->rst)
        {
            bpf_printk("INGRESS [*] RST received");
            conn->state = BPF_TCP_CLOSE;
            // bpf_spin_unlock(&conn->lock);
            bpf_map_delete_elem(&conn_table, &key);
            return XDP_DROP;
        }
        else if (tcp->ack && tcp->psh)
        {
            bpf_printk("INGRESS [*] ACK-PSH Received");
        }
        else if (tcp->ack)
        {
            bpf_printk("INGRESS [*] ACK Received");
        }
        else
        {
            bpf_printk("INGRESS: [*] Unknown ---> Debug it");
            goto drop_unlock;
        }
        break;

    case BPF_TCP_FIN_WAIT1:
        bpf_printk("INGRESS [*] BPF_TCP_FIN_WAIT1 CASE");
        if (tcp->ack)
        {
            bpf_printk("INGRESS [*] ACK received");
            conn->state = BPF_TCP_FIN_WAIT2;
        }
        else
        {
            bpf_printk("INGRESS: [*] Unknown ---> Debug it");
            goto drop_unlock;
        }
        break;

    case BPF_TCP_FIN_WAIT2:
        bpf_printk("INGRESS [*] BPF_TCP_FIN_WAIT2 CASE");
        if (tcp->fin)
        {
            bpf_printk("INGRESS [*] FIN received");
            conn->state = BPF_TCP_TIME_WAIT;
        }
        else if(tcp->ack || tcp->psh)
        {
            bpf_printk("ACK (Data) received");
        }
        else
        {
            bpf_printk("INGRESS: [*] Unknown ---> Debug it");
            goto drop_unlock;
        }
        break;

    case BPF_TCP_TIME_WAIT:
        bpf_printk("INGRESS [*] BPF_TCP_TIME_WAIT CASE");
        if (tcp->ack)
        {
            bpf_printk("INGRESS [*] ACK received ----> Terminating Connection");
            conn->state = BPF_TCP_CLOSE;
            // bpf_spin_unlock(&conn->lock);
            bpf_map_delete_elem(&conn_table, &key);
            return XDP_PASS;
        }
        else
        {
            bpf_printk("INGRESS: [*] Unknown ---> Debug it");
            goto drop_unlock;
        }
        break;

    default:
        bpf_printk("INGRESS [*] default CASE");
        goto drop_unlock;
    }

    conn->last_seen = now;
    // bpf_spin_unlock(&conn->lock);
    return XDP_PASS;

drop_unlock:
    // bpf_spin_unlock(&conn->lock);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
