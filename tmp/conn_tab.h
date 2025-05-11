// https://docs.ebpf.io/linux/concepts/pinning/
// https://stackoverflow.com/questions/75831625/sharing-ebpf-maps-between-2-interface
// https://ebpfchirp.substack.com/p/challenge-2-concurrency-issues-with
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


#ifndef __CONN_TAB_H__
#define __CONN_TAB_H__

#include<linux/types.h>
#include <bpf/bpf_helpers.h>

#define ETH_HLEN 14 // ethhdr lenght.
#define TIMEOUT_NS (60ULL * 1000000000ULL) // 60s timeoutt
#define FORMAT "S_port=%d D_port=%d SYN=%d, ACK=%d, FIN=%d, PSH=%d"  // packet printing format


struct conn_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
};

struct conn_value {
    // struct bpf_spin_lock lock;
    __u8 state;
    __u64 last_seen;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct conn_key);
    __type(value, struct conn_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_table SEC(".maps");

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#endif 