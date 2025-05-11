#!/bin/bash

# Make sure this is set, or hardcode it
PYTHON_SCRIPT=${PYTHON_SCRIPT:-"./reduction.py"}

declare -A protocol_table=( 

[HOPOPT]=0
    [ICMP]=1
    [IGMP]=2
    [GGP]=3
    [IPv4]=4
    [ST]=5
    [TCP]=6
    [CBT]=7
    [EGP]=8
    [IGP]=9
    [BBN-RCC-MON]=10
    [NVP-II]=11
    [PUP]=12
    [ARGUS]=13
    [EMCON]=14
    [XNET]=15
    [CHAOS]=16
    [UDP]=17
    [MUX]=18
    [DCN-MEAS]=19
    [HMP]=20
    [PRM]=21
    [XNS-IDP]=22
    [TRUNK-1]=23
    [TRUNK-2]=24
    [LEAF-1]=25
    [LEAF-2]=26
    [RDP]=27
    [IRTP]=28
    [ISO-TP4]=29
    [NETBLT]=30
    [MFE-NSP]=31
    [MERIT-INP]=32
    [DCCP]=33
    [3PC]=34
    [IDPR]=35
    [XTP]=36
    [DDP]=37
    [IDPR-CMTP]=38
    [TP++]=39
    [IL]=40
    [IPv6]=41
    [SDRP]=42
    [IPv6-Route]=43
    [IPv6-Frag]=44
    [IDRP]=45
    [RSVP]=46
    [GRE]=47
    [DSR]=48
    [BNA]=49
    [ESP]=50
    [AH]=51
    [I-NLSP]=52
    [SWIPE]=53
    [NARP]=54
    [Min-IPv4]=55
    [TLSP]=56
    [SKIP]=57
    [IPv6-ICMP]=58
    [IPv6-NoNxt]=59
    [IPv6-Opts]=60
    [CFTP]=62
    [SAT-EXPAK]=64
    [KRYPTOLAN]=65
    [RVD]=66
    [IPPC]=67
    [SAT-MON]=69
    [VISA]=70
    [IPCV]=71
    [CPNX]=72
    [CPHB]=73
    [WSN]=74
    [PVP]=75
    [BR-SAT-MON]=76
    [SUN-ND]=77
    [WB-MON]=78
    [WB-EXPAK]=79
    [ISO-IP]=80
    [VMTP]=81
    [SECURE-VMTP]=82
    [VINES]=83
    [TTP]=84
    [IPTM]=84
    [NSFNET-IGP]=85
    [DGP]=86
    [TCF]=87
    [EIGRP]=88
    [OSPFIGP]=89
    [Sprite-RPC]=90
    [LARP]=91
    [MTP]=92
    [AX.25]=93
    [IPIP]=94
    [MICP]=95
    [SCC-SP]=96
    [ETHERIP]=97
    [ENCAP]=98
    [GMTP]=100
    [IFMP]=101
    [PNNI]=102
    [PIM]=103
    [ARIS]=104
    [SCPS]=105
    [QNX]=106
    [A/N]=107
    [IPCOMP]=108
    [SNP]=109
    [Compaq-Peer]=110
    [IPX-in-IP]=111
    [VRRP]=112
    [PGM]=113
    [L2TP]=115
    [DDX]=116
    [IATP]=117
    [STP]=118
    [SRP]=119
    [UTI]=120
    [SMP]=121
    [PTP]=123
    [ISIS]=124
    [FIRE]=125
    [CRTP]=126
    [CRUDP]=127
    [SSCOPMCE]=128
    [IPLT]=129
    [SPS]=130
    [PIPE]=131
    [SCTP]=132
    [FC]=133
    [RSVP-E2E-IGNORE]=134
    [UDPLite]=136
    [MPLS-in-IP]=137
    [manet]=138
    [HIP]=139
    [Shim6]=140
    [WESP]=141
    [ROHC]=142
    [ETHERNET]=143
    [AGGFRAG]=144
    [NSH]=145
    [Homa]=146
    [BIT-EMU]=147

 )  # (unchanged, as you already defined it well)

port_allow() {
    local port=$1
    if [ -z "$port" ]; then
        echo "[!] Please provide a port number."
        return 1
    fi

    echo "[+] Running Python script to get port key bytes..."
    KEY_BYTES=$(python3 "$PYTHON_SCRIPT" "$port" | grep "To store in bpftool" | sed 's/.*key: //')

    if [ -z "$KEY_BYTES" ]; then
        echo "[!] No key bytes received from Python script."
        exit 1
    fi

    read -ra bytes <<< "$KEY_BYTES"
    if [ ${#bytes[@]} -eq 1 ]; then
        KEY_BYTES="${bytes[0]} 00"
    fi

    echo "    -> Key Bytes: $KEY_BYTES"
    echo "[+] Updating map with blocked port..."
    sudo bpftool map update name port_blocker key $KEY_BYTES value 0
}


port_block() {
    local port=$1
    if [ -z "$port" ]; then
        echo "[!] Please provide a port number."
        return 1
    fi

    echo "[+] Running Python script to get port key bytes..."
    KEY_BYTES=$(python3 "$PYTHON_SCRIPT" "$port" | grep "To store in bpftool" | sed 's/.*key: //')

    if [ -z "$KEY_BYTES" ]; then
        echo "[!] No key bytes received from Python script."
        exit 1
    fi

    read -ra bytes <<< "$KEY_BYTES"
    if [ ${#bytes[@]} -eq 1 ]; then
        KEY_BYTES="${bytes[0]} 00"
    fi

    echo "    -> Key Bytes: $KEY_BYTES"
    echo "[+] Updating map with blocked port..."
    sudo bpftool map update name port_blocker key $KEY_BYTES value 1
}



ip_block() {
    local ip=$1
    IFS='.' read -ra parts <<< "$ip"
    if [ ${#parts[@]} -ne 4 ]; then
        echo "Invalid IP: $ip"
        return 1
    fi
    sudo bpftool map update name blocked_ips key ${parts[0]} ${parts[1]} ${parts[2]} ${parts[3]} value 1
}

ip_allow() {
    local ip=$1
    IFS='.' read -ra parts <<< "$ip"
    if [ ${#parts[@]} -ne 4 ]; then
        echo "Invalid IP: $ip"
        return 1
    fi
    sudo bpftool map update name blocked_ips key ${parts[0]} ${parts[1]} ${parts[2]} ${parts[3]} value 0
}

protocol_block() {
    local proto_name=$1
    local proto_num=${protocol_table[$proto_name]}
    if [ -z "$proto_num" ]; then
        echo "[!] Unknown protocol name: $proto_name"
        return 1
    fi
    echo "[+] Blocking protocol: $proto_name ($proto_num)"
    sudo bpftool map update name black_protocol key $proto_num value 1
}

protocol_allow() {
    local proto_name=$1
    local proto_num=${protocol_table[$proto_name]}
    if [ -z "$proto_num" ]; then
        echo "[!] Unknown protocol name: $proto_name"
        return 1
    fi
    echo "[+] Allowing protocol: $proto_name ($proto_num)"
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
}

disable_rl() {
    sudo bpftool map update name options key 1 value 0
}

enable_mafw() {
    echo "[+] Enabling MAFW (eBPF program)..."
    clang -O2 -g -target bpf -c main.c -o main.o 
    sudo bpftool prog load main.o /sys/fs/bpf/main
    sudo bpftool net attach xdp name init dev wlo1 
}

disable_mafw() {
    echo "[+] Disabling MAFW..."
    sudo bpftool net detach xdp dev wlo1
    sudo rm /sys/fs/bpf/main
    # Not removing /sys/fs/bpf/main for persistence.
}

main() {
    local cmd=$1
    shift

    case "$cmd" in
        port_block) port_block "$@" ;;
        port_allow) port_allow "$@" ;;
        ip_block) ip_block "$@" ;;
        ip_allow) ip_allow "$@" ;;
        protocol_block) protocol_block "$@" ;;
        protocol_allow) protocol_allow "$@" ;;
        enable_rpf) enable_rpf ;;
        disable_rpf) disable_rpf ;;
        enable_spi) enable_spi ;;
        disable_spi) disable_spi ;;
        enable_rl) enable_rl ;;
        disable_rl) disable_rl ;;
        enable_mafw) enable_mafw ;;
        disable_mafw) disable_mafw ;;
        *)
            echo "[!] Unknown command: $cmd"
            echo "Available commands:"
            echo "  port_block, port_allow"
            echo "  ip_block <ip>, ip_allow <ip>"
            echo "  protocol_block <name>, protocol_allow <name>"
            echo "  enable_rpf, disable_rpf"
            echo "  enable_spi, disable_spi"
            echo "  enable_rl, disable_rl"
            echo "  enable_mafw, disable_mafw"
            return 1
            ;;
    esac
}

main "$@"
