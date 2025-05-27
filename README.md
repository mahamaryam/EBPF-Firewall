# `mafw` (Modular Advanced Firewall)

A modular, easy-to-use firewall control script for Linux using eBPF, with advanced features such as dynamic protocol/IP/port based filtering, optional stateful and rate-limiting logic, and robust status output. Requires Linux with [bpftool](https://man7.org/linux/man-pages/man8/bpftool.8.html), [clang](https://clang.llvm.org/), and [jq](https://stedolan.github.io/jq/).

---

## Features

- Block/Allow specific **IP addresses**, **CIDR ranges**, **TCP/UDP ports**, or **protocols**.
- Enable/Disable:
  - **Stateful Packet Inspection** (SPI)
  - **Reverse Path Filtering** (RPF)
  - **Rate Limiting** (RL) per source IP
- Load/unload the entire eBPF-based firewall on any specified network interface.
- Query the current status and feature enablement with colored CLI output.
- Friendly command-line interface with usage and auto-completion help.

---

## Requirements

- Linux kernel with eBPF and XDP support
- `bpftool`, `clang`, `gcc` (recommended), `jq`
- **Root privileges** to load/unload firewall or modify eBPF maps

---

## Installation

1. **Clone or download** this script and related C sources (eBPF programs) to your system.
2. Ensure BPF programs (`main.c`, `egress.c`, etc.) and `mafw` script are present in current directory
---

## Usage

```bash
./mafw <command> [arguments...]
```

### Main Commands

| Command                      | Description                                                           |
|------------------------------|-----------------------------------------------------------------------|
| `enable_mafw <iface>`        | Enable firewall on network interface `<iface>`                        |
| `disable_mafw <iface>`       | Disable firewall on network interface `<iface>`                       |
| `port_block <port>`          | Block specific TCP/UDP port                                          |
| `port_allow <port>`          | Allow specific TCP/UDP port                                          |
| `ip_block <ip>`              | Block an IPv4 address (e.g., `192.168.1.2`)                          |
| `ip_allow <ip>`              | Allow an IPv4 address                                                |
| `protocol_block <proto>`     | Block protocol (e.g., `TCP`, `UDP`, `ICMP`)                          |
| `protocol_allow <proto>`     | Allow protocol                                                       |
| `block_range <CIDR>`         | Block a CIDR range (e.g., `192.168.1.0/24`)                          |
| `allow_range <CIDR>`         | Allow a CIDR range                                                   |
| `enable_rpf`                 | Enable reverse path filtering                                        |
| `disable_rpf`                | Disable reverse path filtering                                       |
| `enable_spi`                 | Enable stateful packet inspection                                    |
| `disable_spi`                | Disable stateful packet inspection                                   |
| `enable_rl`                  | Enable rate limiting per IP                                          |
| `disable_rl`                 | Disable rate limiting                                                |
| `set_rl <ip> <limit>`        | Set rate limit for IP (e.g., `1.2.3.4 100`)                          |
| `status`                     | Show overall firewall status and feature enablement                  |
| `-h`, `--help`               | Show command summary and examples                                    |
| `-v`, `--version`            | Show version number                                                  |

---

## Examples

Enable firewall on interface `eth0`:

```bash
./mafw enable_mafw eth0
```

Block port 80:

```bash
./mafw port_block 80
```

Block a CIDR range:

```bash
./mafw block_range 10.1.2.0/24
```

Enable stateful inspection and rate-limiting:

```bash
./mafw enable_spi
./mafw enable_rl
```

**Check status:**
```bash
./mafw status
```

---

## Notes

- You must always run `enable_mafw <iface>` before other mapping operations.
- Most actions take effect immediately (unless eBPF programs are not loaded).
- See all supported protocol names in the script or try common ones like `TCP`, `UDP`, `ICMP`.

---

## Troubleshooting

- If you receive a warning about missing dependencies, install `bpftool`, `clang`, `gcc`, and `jq`.
- If commands fail due to insufficient privilege, run as root or via `sudo`.
- To completely remove all maps/programs, use `disable_mafw <iface>`.
- Use the `status` command to verify firewall and feature states.

---

## Extending

- Add or edit protocol names in the `protocol_table` at the script top as needed.
- IPv6 support can be added by adjusting parsing and eBPF programs.

---

**Questions or suggestions? Open an issue or a pull request!**
