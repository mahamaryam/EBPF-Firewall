# Mini Firewall 
- Spin lock and unlock instructions are commented out for debugging purposes, as we cannot call functions (e.g., bpf_printk) while holding a lock.

## Dependencies

- [xdp-loader](https://github.com/xdp-project/xdp-tools.git)
- [ecc and ecli](https://eunomia.dev/tutorials/1-helloworld/)
- [bpftool](https://github.com/libbpf/bpftool)

## How to run

Just run `make run` command.

## Note

@tchook {"ifindex":6, "attach_point":"BPF_TC_EGRESS"}

- You can notice above line  in our `egress.c`. This line tells ecli to attach this TC program to our **interface number 6**  and monitor **EGRESS** traffic.
To get interface number, you can use command `ip a`.

- Change the `Makefile` and `egress.c` according to your network interface. In `Makefile`, I have used interface `test`.

## Work in Progress

Some edge cases still needed to be handled to maintain the TCP states properly. i.e, 

- When user presses ctrl + D or ctrl + C before entering his password.
