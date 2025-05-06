#!/bin/bash

set -e

INTERFACE="wlo1"
OBJ_FILE="block_ip.o"
PROG_PIN="/sys/fs/bpf/block_ip"
MAP_PIN="/sys/fs/bpf/blocked_ips"
MAP_NAME="blocked_ips"
IP_TO_BLOCK="$1"

if [[ -z "$IP_TO_BLOCK" ]]; then
    echo "[!] Usage: $0 <IP_TO_BLOCK>"
    exit 1
fi

# Step 1: Load XDP program
echo "[+] Loading XDP program..."
sudo bpftool prog load "$OBJ_FILE" "$PROG_PIN" type xdp

# Step 2: Get program ID
PROG_ID=$(sudo bpftool prog show | grep -B1 "xdp" | grep -o '^[0-9]*:' | head -n 1 | tr -d :)
if [[ -z "$PROG_ID" ]]; then
    echo "[!] Failed to get XDP program ID."
    exit 1
fi
echo "    -> Program ID: $PROG_ID"

# Step 3: Attach program to interface
echo "[+] Attaching XDP program to $INTERFACE..."
sudo bpftool net attach xdp id "$PROG_ID" dev "$INTERFACE"

# Step 4: Get map ID
echo "[+] Getting map ID for '$MAP_NAME'..."
MAP_ID=$(sudo bpftool map show | grep -B1 "name $MAP_NAME" | grep -o '^[0-9]*:' | tr -d :)
if [[ -z "$MAP_ID" ]]; then
    echo "[!] Failed to find map ID."
    exit 1
fi
echo "    -> Map ID: $MAP_ID"

# Step 5: Pin the map
echo "[+] Pinning map to $MAP_PIN..."
sudo bpftool map pin id "$MAP_ID" "$MAP_PIN"

# Step 6: Split IP and update map
IFS='.' read -r b1 b2 b3 b4 <<< "$IP_TO_BLOCK"
echo "[+] Updating map with key $b1 $b2 $b3 $b4 and value 1..."
sudo bpftool map update pinned "$MAP_PIN" key "$b1" "$b2" "$b3" "$b4" value 0x01

echo "[✓] Blocked IP $IP_TO_BLOCK"

