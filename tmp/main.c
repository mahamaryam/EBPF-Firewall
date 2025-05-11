#include "header.h"
#include "conn_tab.h"

static int __always_inline xdp_drop_ips(struct iphdr *ip)
{

    __u32 decimal_ip = ip->saddr;
    __u8 *ip_value = bpf_map_lookup_elem(&blocked_ips, &decimal_ip);

    if (ip_value)
    {
        if (*ip_value == 0)
            return XDP_PASS;
        if (*ip_value == 1)
            return XDP_DROP;
    }
    return XDP_PASS;
}

static int __always_inline ip_range_blocking(struct iphdr *ip)
{
    __u32 decimal_ip = bpf_ntohl(ip->saddr);

#pragma unroll
    for (int i = 0; i < 50; i++)
    {
        struct ip_mask *ip_get;
        int index = i;
        // separate variable
        /*Clang must know the loop bounds and index are constant. If you use &i directly in bpf_map_lookup_elem, it may prevent unrolling because &i is on the stack and changes each iteration.
        Instead, assign the loop index i to a fixed scalar variable (index) on each iteration. This is a known workaround for unrolling in BPF.And in each of those cases, the index can be
        evaluated as a known immediate value, allowing the verifier to track the pointer safety and avoid rejecting it.
    */
        ip_get = bpf_map_lookup_elem(&ip_blocklist, &index); // add null case.
        if (!ip_get)
            break;
        // return XDP_PASS;
        if ((decimal_ip & ip_get->mask) == (ip_get->ip & ip_get->mask))
           return XDP_DROP;
    }
    // another option to xor the ip->saddr with the ip in my map and then and with the mask to see if all zeroes, then drop.
    return XDP_PASS;
}

static int __always_inline xdp_port_block(struct iphdr *iph, void *data_end)
{
    __u8 protocol = iph->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u16 dst_port = 0;

    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);
        if ((void *)tcph + sizeof(*tcph) > data_end)
           return XDP_DROP;
           
        dst_port = bpf_ntohs(tcph->dest);
    }
    else if (protocol == IPPROTO_UDP)
    {
        struct udphdr *udph = (void *)iph + sizeof(*iph);
        if ((void *)udph + sizeof(*udph) > data_end)
           return XDP_DROP;
           
        dst_port = bpf_ntohs(udph->dest);
    }

    // lookup
    __u8 *blocked = bpf_map_lookup_elem(&port_blocker, &dst_port);
    if (blocked)
    {  
      if(*blocked==1)
         return XDP_DROP;
    } 

    return XDP_PASS;
}

static int __always_inline xdp_protocol_block(struct iphdr *iph)
{
    __u8 protocol = iph->protocol;

    __u8 *blocked = bpf_map_lookup_elem(&black_protocol, &protocol);
    if (blocked)
    {
        if(*blocked==1)
           return XDP_DROP;
           //if 0 then let go. xdp_pass;
    }
    return XDP_PASS;
}
static int __always_inline reverse_path_filtering(struct xdp_md *ctx, struct iphdr *ip)
{

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
static int __always_inline ingress_state(struct iphdr *ip, struct tcphdr *tcp)
{

    struct conn_key key = {};

    key.src_ip = (ip->saddr > ip->daddr) ? ip->saddr : ip->daddr,
    key.dst_ip = (ip->saddr < ip->daddr) ? ip->daddr : ip->saddr,
    key.src_port = (tcp->source > tcp->dest) ? tcp->source : tcp->dest,
    key.dst_port = (tcp->source < tcp->dest) ? tcp->source : tcp->dest,
    key.protocol = ip->protocol; //had a , earlier rather than ;

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
static int __always_inline xdp_rate_limiting(struct iphdr *iph)
{
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
SEC("xdp")
int init(struct xdp_md *ctx)
{

bpf_printk("in the start");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
bpf_printk("i've reached HERE ethernet");
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

    struct iphdr *iph = cursor;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
        bpf_printk("i've reached HERE iphdr");

    struct tcphdr *tcp = (void *)(iph + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    bpf_printk("i've reached HEREtcp");    
    int action = xdp_protocol_block(iph); //1
    if(action==XDP_DROP) return XDP_DROP;
    //pass case
    action = xdp_drop_ips(iph);     if(action==XDP_DROP) return XDP_DROP; //2
    action = ip_range_blocking(iph);     if(action==XDP_DROP) return XDP_DROP;//3
    action = xdp_port_block(iph, data_end);     if(action==XDP_DROP) return XDP_DROP;//4
    
    __u8 _lookup=1;
    __u8 *var;
    var = bpf_map_lookup_elem(&options, &_lookup);
    if(var)
    {
       if(*var==1)
       {
       action = xdp_rate_limiting(iph); 
       if (action==XDP_DROP) 
          return XDP_DROP; 
       } 
       
       }
    
    _lookup = 2;
    var = bpf_map_lookup_elem(&options, &_lookup);
    if(var){
    if(*var == 1)
    {action = reverse_path_filtering(ctx, iph); if(action==XDP_DROP) return XDP_DROP; }//6 
    }
   
    _lookup = 3;
    var = bpf_map_lookup_elem(&options, &_lookup);
    if(var){
    if(*var == 1 && iph->protocol == IPPROTO_TCP)
    {action = ingress_state(iph, tcp); if(action==XDP_DROP) return XDP_DROP; } }//7
    //reserved, 1st index for rate limiting, 2nd index for reverse path filtering, and 3rd for stateful packet inspection. third index to be used in tc too.
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
