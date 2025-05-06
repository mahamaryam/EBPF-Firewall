#!/bin/bash

set -e
#https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
INTERFACE="wlo1"
PIN_PATH="/sys/fs/bpf/protocol_blocker"
MAP_PIN_PATH="/sys/fs/bpf/protocol_block_map"
OBJ_FILE="protocol_blocker.o"
MAP_NAME="protocol_blocke"  # still truncated
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
)

# ==== Ask User for Protocol Name ====
read -p "Enter protocol name (e.g., ICMP, TCP, UDP): " PROTO_NAME
PROTO_NUM=${protocol_table[$PROTO_NAME]}

if [ -z "$PROTO_NUM" ]; then
    echo "[!] Unknown protocol '$PROTO_NAME'. Valid options are:"
    echo "${!protocol_table[@]}"
    exit 1
fi

echo "[+] Protocol '$PROTO_NAME' maps to protocol number $PROTO_NUM"

# ==== Load eBPF Program ====
echo "[+] Loading eBPF program..."
sudo bpftool prog load $OBJ_FILE $PIN_PATH type xdp || {
    echo "[!] Failed to load program."
    exit 1
}

# ==== Get Program ID ====
echo "[+] Getting XDP program ID..."
PROG_ID=$(sudo bpftool prog | grep -B1 "xdp" | grep -o '^[0-9]*:' | head -n 1)
PROG_ID=${PROG_ID%:}

if [ -z "$PROG_ID" ]; then
    echo "[!] Could not find XDP program ID."
    exit 1
fi
echo "    -> Program ID: $PROG_ID"

# ==== Attach to Interface ====
echo "[+] Attaching program to interface $INTERFACE..."
sudo bpftool net attach xdp id $PROG_ID dev $INTERFACE || {
    echo "[!] Failed to attach XDP program."
    exit 1
}

# ==== Get Map ID ====
echo "[+] Getting map ID by name '$MAP_NAME'..."
MAP_ID=$(sudo bpftool map list | grep -B1 "name $MAP_NAME" | grep -o '^[0-9]*:' | sed 's/://')

if [ -z "$MAP_ID" ]; then
    echo "[!] Could not find map ID for name '$MAP_NAME'."
    exit 1
fi
echo "    -> Map ID: $MAP_ID"

# ==== Pin the Map ====
echo "[+] Pinning map to $MAP_PIN_PATH..."
sudo bpftool map pin id $MAP_ID $MAP_PIN_PATH || {
    echo "[!] Failed to pin map."
    exit 1
}

# ==== Insert Protocol Number into Map ====
echo "[+] Blocking protocol number $PROTO_NUM..."
sudo bpftool map update pinned $MAP_PIN_PATH key hex $(printf "%02x" $PROTO_NUM) value hex 01 || {
    echo "[!] Failed to update map."
    exit 1
}

echo "[+] Protocol '$PROTO_NAME' blocked successfully!"

