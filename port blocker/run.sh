#!/bin/bash

# ==== CONFIGURATION ====
INTERFACE="wlo1"
BPF_OBJ="port_blocker.o"
PROG_PIN="/sys/fs/bpf/port_blocker"
MAP_PIN="/sys/fs/bpf/port_block_map"
PYTHON_SCRIPT="reduction.py"
MAP_NAME="port_blocker"

# ==== STEP 1: Load eBPF Program ====
echo "[+] Loading eBPF program..."
sudo bpftool prog load $BPF_OBJ $PROG_PIN type xdp || {
    echo "[!] Failed to load program."
    exit 1
}

# ==== STEP 2: Get Program ID ====
echo "[+] Getting XDP program ID..."
PROG_ID=$(sudo bpftool prog | grep -B1 "xdp" | grep -o '^[0-9]*:' | head -n 1)
PROG_ID=${PROG_ID%:}

if [ -z "$PROG_ID" ]; then
    echo "[!] Could not find XDP program ID."
    exit 1
fi
echo "    -> Program ID: $PROG_ID"

# ==== STEP 3: Attach to Interface ====
echo "[+] Attaching program to interface $INTERFACE..."
sudo bpftool net attach xdp id $PROG_ID dev $INTERFACE || {
    echo "[!] Failed to attach XDP program."
    exit 1
}

# ==== STEP 4: Find Map ID by Name ====
echo "[+] Getting map ID by name '$MAP_NAME'..."
MAP_ID=$(sudo bpftool map list | grep -B1 "name $MAP_NAME" | grep -o '^[0-9]*:' | sed 's/://')

if [ -z "$MAP_ID" ]; then
    echo "[!] Could not find map ID for name '$MAP_NAME'."
    exit 1
fi
echo "    -> Map ID: $MAP_ID"

# ==== STEP 5: Pin the Map ====
echo "[+] Pinning map to $MAP_PIN..."
sudo bpftool map pin id $MAP_ID $MAP_PIN || {
    echo "[!] Failed to pin map."
    exit 1
}

# ==== STEP 6: Run Python Script to Get Port ====
echo "[+] Running Python script to get port key bytes..."
KEY_BYTES=$(python3 $PYTHON_SCRIPT | grep "To store in bpftool" | sed 's/.*key: //')

if [ -z "$KEY_BYTES" ]; then
    echo "[!] No key bytes received from Python script."
    exit 1
fi
echo "    -> Key Bytes: $KEY_BYTES"

# ==== STEP 7: Update Map to Block Port ====
echo "[+] Updating map with blocked port..."
sudo bpftool map update pinned $MAP_PIN key $KEY_BYTES value 1 || {
    echo "[!] Failed to update map with port."
    exit 1
}

echo "[✓] Successfully blocked port using XDP!"

