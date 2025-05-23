#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include "conn_tab.h"
#include "header.h"

static int __always_inline tc_egress_firewall(struct iphdr ip, struct tcphdr tcp)
{
    struct conn_key key = {};
    key.src_ip = (ip.saddr > ip.daddr) ? ip.saddr : ip.daddr;
    key.dst_ip = (ip.saddr < ip.daddr) ? ip.daddr : ip.saddr;
    key.src_port = (tcp.source > tcp.dest) ? tcp.source : tcp.dest;
    key.dst_port = (tcp.source < tcp.dest) ? tcp.source : tcp.dest;
    key.protocol = ip.protocol;

    struct conn_value *conn = bpf_map_lookup_elem(&conn_table, &key);
    __u64 now = bpf_ktime_get_ns();

    bpf_printk(FORMAT, bpf_ntohs(key.src_port), bpf_ntohs(key.dst_port), tcp.syn, tcp.ack, tcp.fin, tcp.psh);

    if (!conn)
    {
        if (tcp.syn && !tcp.ack)
        {
            struct conn_value new_conn = {};
            new_conn.state = BPF_TCP_SYN_SENT;
            new_conn.last_seen = now;
            int ret = bpf_map_update_elem(&conn_table, &key, &new_conn, BPF_ANY);
            if (ret < 0)
                bpf_printk("EGRESS [*] Error in loading packet to map.");
            bpf_printk("EGRESS: [*] SYN sent");
            return TC_ACT_OK;
        }
        else
        {
            bpf_printk("EGRESS [*] New Connection ---> Not SYN ---> Dropping");
            return TC_ACT_SHOT;
        }
    }

    // bpf_spin_lock(&conn->lock);

    switch (conn->state)
    {
    case BPF_TCP_SYN_SENT:
        bpf_printk("EGRESS [*] BPF_TCP_SYN_SENT Case");
        if (!tcp.syn && tcp.ack)
        {
            bpf_printk("EGRESS [*] ACK sent");
            conn->state = BPF_TCP_ESTABLISHED;
        }
        else if (tcp.rst)
        {
            bpf_printk("EGRESS [*] RST Recieved. Terminating Connection");
            conn->state = BPF_TCP_CLOSE;
            // bpf_spin_unlock(&conn->lock);
            bpf_map_delete_elem(&conn_table, &key);
            return TC_ACT_OK;
        }
        else
        {
            // bpf_spin_unlock(&conn->lock);
            bpf_printk("EGRESS [*] Unkown ---> Debug it");
            return TC_ACT_SHOT;
        }
        break;

    case BPF_TCP_SYN_RECV:
        bpf_printk("EGRESS [*] BPF_TCP_SYN_RECV Case");
        if (tcp.ack && tcp.syn)
        {
            bpf_printk("EGRESS SYN-ACK sent");
            conn->state = BPF_TCP_SYN_SENT;
        }
        else if (tcp.ack && !tcp.syn)
        {
            bpf_printk("EGRESS [*] ACK sent");
            conn->state = BPF_TCP_ESTABLISHED;
        }
        else
        {
            // bpf_spin_unlock(&conn->lock);
            bpf_printk("EGRESS [*] Unkown ---> Debug it");
            return TC_ACT_SHOT;
        }
        break;

    case BPF_TCP_ESTABLISHED:
        bpf_printk("EGRESS [*] BPF_TCP_ESTABLISHED Case");
        if (tcp.fin)
        {
            bpf_printk("EGRESS [*] FIN sent");
            conn->state = BPF_TCP_FIN_WAIT1;
        }
        // PSH (Push) flag tells the nreceiver to immediately pass the received data up to the applicatio, useful for things like interactive SSH sessions where you want characters to appear immediately
        else if (tcp.ack && tcp.psh)
        {
            bpf_printk("EGRESS [*] ACK-PSH sent");
        }
        // During a TCP connection, ACK is sent on regular internals to confirm that the connection is still active.
        else if (tcp.ack)
        {
            bpf_printk("EGRESS [*] ACK sent");
        }
        else
        {
            // bpf_spin_unlock(&conn->lock);
            bpf_printk("EGRESS [*] Unkown ---> Debug it");
            return TC_ACT_SHOT;
        }
        break;

    case BPF_TCP_FIN_WAIT1:
        bpf_printk("EGRESS [*] BPF_TCP_FIN_WAIT1 Case");
        if (tcp.ack)
        {
            bpf_printk("EGRESS [*] ACK sent");
            conn->state = BPF_TCP_FIN_WAIT2;
        }
        else
        {
            // bpf_spin_unlock(&conn->lock);
            bpf_printk("EGRESS [*] Unkown ---> Debug it");
            return TC_ACT_SHOT;
        }
        break;

    case BPF_TCP_FIN_WAIT2:
        bpf_printk("EGRESS [*] BPF_TCP_FIN_WAIT2 Case");
        if (tcp.fin)
        {
            bpf_printk("EGRESS [*] FIN sent");
            conn->state = BPF_TCP_TIME_WAIT;
        }
        // One side still send data after sending ACK once it receives FIN.
        else if (tcp.ack || tcp.psh)
        {
            bpf_printk("ACK (Data) sent");
        }
        else
        {
            // bpf_spin_unlock(&conn->lock);
            bpf_printk("EGRESS [*] Unkown ---> Debug it");
            return TC_ACT_SHOT;
        }
        break;

    case BPF_TCP_TIME_WAIT:
        bpf_printk("EGRESS [*] BPF_TCP_TIME_WAIT Case");
        if (tcp.ack)
        {
            bpf_printk("EGRESS [*] ACK sent ----> Terminating Connection");
            conn->state = BPF_TCP_CLOSE;
            // bpf_spin_unlock(&conn->lock);
            bpf_map_delete_elem(&conn_table, &key);
            return TC_ACT_OK;
        }
        else
        {
            // bpf_spin_unlock(&conn->lock);
            bpf_printk("EGRESS [*] Unkown ---> Debug it");
            return TC_ACT_SHOT;
        }
        break;

    default:
        // bpf_spin_unlock(&conn->lock);
        bpf_printk("EGRESS [*] Default Case ---> Dropping");
        return TC_ACT_SHOT;
    }

    conn->last_seen = now;
    // bpf_spin_unlock(&conn->lock);
    return TC_ACT_OK;
}

SEC("classifier")
int init(struct __sk_buff *skb)
{
    __u8 _lookup = 3;       // index 3 is for status (enabled/disabled) of TCP statefull firewall
    __u8 *var = bpf_map_lookup_elem(&options, &_lookup);
    if (var)
    {
        if (*var == 1)
        {
            struct iphdr ip;
            struct tcphdr tcp;

            if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
                return TC_ACT_SHOT;

            if (ip.protocol != IPPROTO_TCP)
                return TC_ACT_OK;

            __u32 ip_header_size = ip.ihl * 4;
            if (bpf_skb_load_bytes(skb, ETH_HLEN + ip_header_size, &tcp, sizeof(tcp)) < 0)
                return TC_ACT_SHOT;

            __u8 action = tc_egress_firewall(ip, tcp);
            if (action == TC_ACT_SHOT)
                return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
