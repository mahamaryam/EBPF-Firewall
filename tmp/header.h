#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>  
#define AF_INET 2


// ip blocker
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128); //max ip blocked
    __type(key, __u32); //ip
    __type(value, __u8); //whether or not ip is blocked
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

//protocol blocking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8);  //protocol number
    __type(value, __u8); //1 = blocked 0 unblocked, no 0 needed. dummy shit.
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} black_protocol SEC(".maps");

//blocked ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  //port number
    __type(value, __u8); //0 or 1.
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_blocker SEC(".maps");

// ip range
struct ip_mask {
    __u32 ip;
    __u32 mask;
};

//for ip range blocking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50);
    __type(key, int);
    __type(value, struct ip_mask);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_blocklist SEC(".maps");

//fixed window
//enter ip in reverse. 192.168.1.10---> 10 1 168 192
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, __u8); //can store up to the user defined number... of packets allowed per 10seconds.
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} fixed_window_per_ip SEC(".maps");

//second struct for holding the current packets. cmp with fixed_window_per_ip.value to see if ==. have ip as key.
struct 
{
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries,2048);
__type(key, __u32); //ip
__type(value, __u8); //current packets per 10s.
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} current_packets SEC(".maps");
//above for fixed window too

//no struct for reverse path filtering.

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);  // Must be ≥ 2 for index 1 to be valid
    __type(key, __u8); //index
    __type(value, __u8); //value either 0 or 1
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} options SEC(".maps");





