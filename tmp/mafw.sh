#!/usr/bin/env bash

set -euo pipefail

VERSION="1.1"

# Check required dependencies
check_deps() {
    for cmd in bpftool clang jq; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[FATAL] Missing dependency: $cmd; please install it."
            exit 1
        fi
    done
}

declare -A protocol_table=(
    [HOPOPT]=0 [ICMP]=1 [IGMP]=2 [GGP]=3 [IPV4]=4 [ST]=5
    [TCP]=6 [CBT]=7 [EGP]=8 [IGP]=9 [BBNRCCMON]=10 [NVP2]=11 [PUP]=12
    [ARGUS]=13 [EMCON]=14 [XNET]=15 [CHAOS]=16 [UDP]=17 [MUX]=18
    [DCNMEAS]=19 [HMP]=20 [PRM]=21 [XNSIDP]=22 [TRUNK1]=23 [TRUNK2]=24
    [LEAF1]=25 [LEAF2]=26 [RDP]=27 [IRTP]=28 [ISOTP4]=29 [NETBLT]=30
    [MFORENSP]=31 [MERITINP]=32 [DCCP]=33 [THREEPC]=34 [IDPR]=35 [XTP]=36
    [DDP]=37 [IDPRCMTP]=38 [TPPP]=39 [IL]=40 [IPV6]=41 [SDRP]=42
    [IPV6ROUTE]=43 [IPV6FRAG]=44 [IDRP]=45 [RSVP]=46 [GRE]=47 [DSR]=48
    [BNA]=49 [ESP]=50 [AH]=51 [INLSP]=52 [SWIPE]=53 [NARP]=54 [MINIPV4]=55
    [TLSP]=56 [SKIP]=57 [IPV6ICMP]=58 [IPV6NONXT]=59 [IPV6OPTS]=60
    [CFTP]=62 [SATEXPAK]=64 [KRYPTOLAN]=65 [RVD]=66 [IPPC]=67 [SATMON]=69
    [VISA]=70 [IPCV]=71 [CPNX]=72 [CPHB]=73 [WSN]=74 [PVP]=75 [BRSATMON]=76
    [SUNND]=77 [WBMON]=78 [WBEXPAK]=79 [ISOIP]=80 [VMTP]=81 [SECUREVMTP]=82
    [VINES]=83 [TTP]=84 [IPTM]=84 [NSFNETIGP]=85 [DGP]=86 [TCF]=87 [EIGRP]=88
    [OSPFIGP]=89 [SPRITERPC]=90 [LARP]=91 [MTP]=92 [AX25]=93 [IPIP]=94
    [MICP]=95 [SCCSP]=96 [ETHERIP]=97 [ENCAP]=98 [GMTP]=100 [IFMP]=101
    [PNNI]=102 [PIM]=103 [ARIS]=104 [SCPS]=105 [QNX]=106 [AN]=107 [IPCOMP]=108
    [SNP]=109 [COMPAQPEER]=110 [IPXINIP]=111 [VRRP]=112 [PGM]=113
    [L2TP]=115 [DDX]=116 [IATP]=117 [STP]=118 [SRP]=119 [UTI]=120 [SMP]=121
    [PTP]=123 [ISIS]=124 [FIRE]=125 [CRTP]=126 [CRUDP]=127 [SSCOPMCE]=128
    [IPLT]=129 [SPS]=130 [PIPE]=131 [SCTP]=132 [FC]=133 [RSVPE2EIGNORE]=134
    [UDPLITE]=136 [MPLSINIP]=137 [MANET]=138 [HIP]=139 [SHIM6]=140
    [WESP]=141 [ROHC]=142 [ETHERNET]=143 [AGGFRAG]=144 [NSH]=145 [HOMA]=146
    [BITEMU]=147
)
# Add aliases:
protocol_table["ICMPv6"]=58
protocol_table["ICMP6"]=58

be_to_le() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: be_to_le <port>"
        return 1
    fi

    port="$1"

    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 0 ] || [ "$port" -gt 65535 ]; then
        echo "[!] Invalid port: Port must be an integer between 0 and 65535."
        return 1
    fi

    lo_byte=$((port & 0xFF))
    hi_byte=$(((port >> 8) & 0xFF))
    echo "$lo_byte $hi_byte"
}

port_allow() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: port_allow <port>"
        return 1
    fi
    local port=$1
    KEY_BYTES=$(be_to_le "$port") || return 1
    echo "[+] Allowing port $port -> Key Bytes: $KEY_BYTES"
    sudo bpftool map update name port_blocker key $KEY_BYTES value 0
}

port_block() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: port_block <port>"
        return 1
    fi
    local port=$1
    KEY_BYTES=$(be_to_le "$port") || return 1
    echo "[+] Blocking port $port -> Key Bytes: $KEY_BYTES"
    sudo bpftool map update name port_blocker key $KEY_BYTES value 1
}

is_valid_ip() {
    local ip=$1
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -ra a <<<"$ip"
    for x in "${a[@]}"; do [[ $x -gt 255 ]] && return 1; done
    return 0
}

ip_block() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: ip_block <ip>"
        return 1
    fi
    local ip=$1
    if ! is_valid_ip "$ip"; then
        echo "[!] Invalid IPv4: $ip"
        return 1
    fi
    IFS='.' read -ra parts <<<"$ip"
    sudo bpftool map update name blocked_ips key ${parts[0]} ${parts[1]} ${parts[2]} ${parts[3]} value 1
}

ip_allow() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: ip_allow <ip>"
        return 1
    fi
    local ip=$1
    if ! is_valid_ip "$ip"; then
        echo "[!] Invalid IPv4: $ip"
        return 1
    fi
    IFS='.' read -ra parts <<<"$ip"
    sudo bpftool map update name blocked_ips key ${parts[0]} ${parts[1]} ${parts[2]} ${parts[3]} value 0
}

protocol_block() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: protocol_block <protocol>"
        return 1
    fi
    local proto_name="${1^^}"
    proto_name=${proto_name//[^A-Z0-9]/}
    local proto_num="${protocol_table[$proto_name]:-}"
    if [[ -z "$proto_num" ]]; then
        echo "[!] Unknown protocol name: $1"
        return 1
    fi
    echo "[+] Blocking protocol: $1 ($proto_num)"
    sudo bpftool map update name black_protocol key $proto_num value 1
}

protocol_allow() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: protocol_allow <protocol>"
        return 1
    fi
    local proto_name="${1^^}"
    proto_name=${proto_name//[^A-Z0-9]/}
    local proto_num="${protocol_table[$proto_name]:-}"
    if [[ -z "$proto_num" ]]; then
        echo "[!] Unknown protocol name: $1"
        return 1
    fi
    echo "[+] Allowing protocol: $1 ($proto_num)"
    sudo bpftool map update name black_protocol key $proto_num value 0
}

enable_rpf() {
    sudo bpftool map update name options key 2 value 1
}

disable_rpf() {
    sudo bpftool map update name options key 2 value 0
}

enable_spi() {
    sudo bpftool map update name options key 3 value 1
}

disable_spi() {
    sudo bpftool map update name options key 3 value 0
}

enable_rl() {
    sudo bpftool map update name options key 1 value 1
    if command -v gcc >/dev/null 2>&1; then
        gcc saved.c -o saved -lbpf
        sudo ./saved &
    else
        echo "[!] gcc not installed; skipping saved.c run."
    fi
}

disable_rl() {
    sudo bpftool map update name options key 1 value 0
}

set_rl() {
    if [ $# -ne 2 ]; then
        echo "[!] Usage: set_rl <IP_ADDRESS> <PACKET_LIMIT>"
        return 1
    fi

    local IP="$1"
    local LIMIT="$2"

    if ! is_valid_ip "$IP"; then
        echo "[!] Invalid IPv4: $IP"
        return 1
    fi

    IFS='.' read -r o1 o2 o3 o4 <<<"$IP"
    # Reverse IP bytes for little-endian format
    KEY="$o4 $o3 $o2 $o1"
    sudo bpftool map update pinned /sys/fs/bpf/fixed_window_per_ip key $KEY value $LIMIT
}

enable_mafw() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: enable_mafw <interface>"
        return 1
    fi
    local INTERFACE="$1"
    echo "[+] Enabling MAFW (eBPF program) on interface '$INTERFACE'..."
    echo "    [*] Loading XDP ..."
    clang -O2 -g -target bpf -c main.c -o main.o || { echo "[!] Failed to compile main.c"; disable_mafw "$INTERFACE"; return 1; }
    sudo bpftool prog load main.o /sys/fs/bpf/main
    sudo bpftool net attach xdp pinned /sys/fs/bpf/main dev "$INTERFACE"
    echo "    [*] Loading TC ..."
    clang -O2 -g -target bpf -c egress.c -o egress.o || { echo "[!] Failed to compile egress.c"; disable_mafw "$INTERFACE"; return 1; }
    sudo bpftool prog load egress.o /sys/fs/bpf/egress
    sudo tc qdisc add dev "$INTERFACE" clsact
    sudo tc filter add dev "$INTERFACE" egress bpf da object-pinned /sys/fs/bpf/egress
}

disable_mafw() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: disable_mafw <interface>"
        return 1
    fi
    local INTERFACE="$1"
    echo "[+] Disabling MAFW on interface '$INTERFACE'..."
    echo "    [*] Unloading XDP ..."
    sudo bpftool net detach xdp dev "$INTERFACE" >/dev/null 2>&1 || true
    echo "    [*] Unloading TC ..."
    sudo tc filter del dev "$INTERFACE" egress >/dev/null 2>&1 || true
    sudo tc qdisc del dev "$INTERFACE" clsact >/dev/null 2>&1 || true
    rm /tmp/mafw_range_counter 2>/dev/null

    # Remove pinned maps & programs (all errors ignored)
    for map in black_protocol blocked_ips conn_table current_packets fixed_window \
        fixed_window_per_ip ip_blocklist port_blocker options; do
        sudo rm /sys/fs/bpf/$map 2>/dev/null || true
    done
    for prog in main egress; do
        sudo rm /sys/fs/bpf/$prog 2>/dev/null || true
    done
}

block_range() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: block_range <IP/CIDR>"
        return 1
    fi
    local cidr_ip="$1"
    local ip="${cidr_ip%%/*}"
    local cidr="${cidr_ip##*/}"

    if ! is_valid_ip "$ip" || ! [[ "$cidr" =~ ^[0-9]+$ ]] || ((cidr < 1 || cidr > 32)); then
        echo "[!] Invalid input format. Use: block_range <IP/CIDR> (e.g., 192.168.0.1/24)"
        return 1
    fi

    IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
    ip_rev_hex=$(printf "%02x %02x %02x %02x" $o4 $o3 $o2 $o1)

    full_mask=$(((0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF))
    mask_bytes=$(printf "%02x %02x %02x %02x" $(((full_mask >> 24) & 0xFF)) $(((full_mask >> 16) & 0xFF)) $(((full_mask >> 8) & 0xFF)) $((full_mask & 0xFF)))
    mask_rev_hex=$(echo "$mask_bytes" | awk '{print $4, $3, $2, $1}')
    value_hex="$ip_rev_hex $mask_rev_hex"

    local counter_file="/tmp/mafw_range_counter"
    local index=$(cat "$counter_file" 2>/dev/null || echo 0)

    if ((index >= 50)); then
        echo "[!] Cannot add more than 50 entries. Limit reached."
        return 1
    fi

    key_hex=$(printf "%08x" $index | sed 's/../& /g' | awk '{print $4, $3, $2, $1}')
    echo "[+] Blocking range $cidr_ip"
    echo "    -> Key: $key_hex (index $index)"
    echo "    -> Value: $value_hex"
    sudo bpftool map update name ip_blocklist key hex $key_hex value hex $value_hex
    echo $((index + 1)) >"$counter_file"
}

allow_range() {
    if [ $# -ne 1 ]; then
        echo "[!] Usage: allow_range <IP/CIDR>"
        return 1
    fi
    local cidr_ip="$1"
    local ip="${cidr_ip%%/*}"
    local cidr="${cidr_ip##*/}"

    if ! is_valid_ip "$ip" || ! [[ "$cidr" =~ ^[0-9]+$ ]] || ((cidr < 1 || cidr > 32)); then
        echo "[!] Invalid input format. Use: allow_range <IP/CIDR> (e.g., 192.168.0.1/24)"
        return 1
    fi

    IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
    local ip_int=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
    local mask_int=$(((0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF ))
    local found=0

    while IFS= read -r entry; do
        entry_ip=$(echo "$entry" | jq '.value.ip')
        entry_mask=$(echo "$entry" | jq '.value.mask')
        entry_key=$(echo "$entry" | jq '.key')

        if [[ "$entry_ip" == "$ip_int" && "$entry_mask" == "$mask_int" ]]; then
            key_hex=$(printf "%08x" "$entry_key" | sed 's/../& /g' | awk '{print $4, $3, $2, $1}')
            echo "    [+] Match found at key: $entry_key"
            echo "    [+] Updating key $key_hex with value 00 00 00 00 ff ff ff ff"
            sudo bpftool map update name ip_blocklist key hex $key_hex value hex 00 00 00 00 ff ff ff ff
            found=1
        fi
    done < <(sudo bpftool map dump name ip_blocklist | jq -c '.[]')

    if [[ "$found" -eq 0 ]]; then
        echo "[!] No matching entry found for $cidr_ip"
    fi
}

RED=$(tput setaf 1)
BOLD=$(tput bold)
RESET=$(tput sgr0)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
GREEN=$(tput setaf 2)

print_usage() {

    echo ""
    echo "${BOLD}Usage:${RESET} ${CYAN}$0${RESET} ${YELLOW}<command>${RESET} [options]"
    echo ""
    echo "${BOLD}Available commands:${RESET}"
    echo "  ${GREEN}port_block${RESET} <port>        Block a port"
    echo "  ${GREEN}port_allow${RESET} <port>        Allow a port"
    echo "  ${GREEN}ip_block${RESET} <ip>            Block an IP address"
    echo "  ${GREEN}ip_allow${RESET} <ip>            Allow an IP address"
    echo "  ${GREEN}protocol_block${RESET} <name>    Block a protocol (e.g. TCP, UDP, ICMP)"
    echo "  ${GREEN}protocol_allow${RESET} <name>    Allow a protocol"
    echo "  ${GREEN}block_range${RESET} <CIDR>       Block an IP range (e.g. 192.168.1.0/24)"
    echo "  ${GREEN}allow_range${RESET} <CIDR>       Allow an IP range (e.g. 192.168.1.0/24)"
    echo "  ${GREEN}set_rl${RESET} <ip> <limit>      Set the rate limit"
    echo "  ${GREEN}enable_rpf${RESET}               Enable reverse path filtering"
    echo "  ${GREEN}disable_rpf${RESET}              Disable reverse path filtering"
    echo "  ${GREEN}enable_spi${RESET}               Enable stateful packet inspection"
    echo "  ${GREEN}disable_spi${RESET}              Disable stateful packet inspection"
    echo "  ${GREEN}enable_rl${RESET}                Enable rate limiting"
    echo "  ${GREEN}disable_rl${RESET}               Disable rate limiting"
    echo "  ${GREEN}enable_mafw${RESET} <iface>      Enable MAFW on given interface"
    echo "  ${GREEN}disable_mafw${RESET} <iface>     Disable MAFW on given interface"
    echo "  ${GREEN}-v|--version${RESET}             Show version information"
    echo ""
    echo "${YELLOW}Note:${RESET} Run ${CYAN}enable_mafw <iface>${RESET} first!"
    echo ""
    echo "Use '${CYAN}$0 --help${RESET}' to show this message."
    echo ""
}

main() {
    
     if (( EUID != 0 )); then
        echo "${RED}${BOLD}[!] Please run as root (sudo).${RESET}"
        exit 1
    fi

    check_deps

    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        -h|--help|"") print_usage; exit 0 ;;
        -v|--version) echo "mafw.sh version $VERSION"; exit 0 ;;
        port_block)    port_block "$@" ;;
        port_allow)    port_allow "$@" ;;
        ip_block)      ip_block "$@" ;;
        ip_allow)      ip_allow "$@" ;;
        protocol_block) protocol_block "$@" ;;
        protocol_allow) protocol_allow "$@" ;;
        block_range)   block_range "$@" ;;
        allow_range)   allow_range "$@" ;;
        enable_rpf)    enable_rpf "$@" ;;
        disable_rpf)   disable_rpf "$@" ;;
        enable_spi)    enable_spi "$@" ;;
        disable_spi)   disable_spi "$@" ;;
        enable_rl)     enable_rl "$@" ;;
        disable_rl)    disable_rl "$@" ;;
        enable_mafw)   enable_mafw "$@" ;;
        disable_mafw)  disable_mafw "$@" ;;
        set_rl)        set_rl "$@" ;;
        *) echo "[!] Unknown command: $cmd"; print_usage; exit 1 ;;
    esac
}

main "$@"   