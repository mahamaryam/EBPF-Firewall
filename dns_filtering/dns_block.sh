#!/bin/bash

set -euo pipefail

MAP_PATH="/sys/fs/bpf/blocked_domains"
MAX_DOMAIN_LEN=256

# Pads domain to 256 bytes with nulls and outputs space-separated hex bytes
pad_key() {
    local domain="$1"
    perl -e '
        use strict;
        use warnings;
        my $domain = $ARGV[0];
        my $max_len = 256;
        my $padded = $domain . ("\0" x ($max_len - length($domain)));
        print join(" ", map { sprintf("%02x", $_) } unpack("C*", $padded));
    ' "$domain"
}

add_domain() {
    local domain="$1"
    local padded_key
    padded_key=$(pad_key "$domain")
    local value="01"

    if bpftool map update pinned "$MAP_PATH" key hex $padded_key value hex $value > /dev/null 2>&1; then
        echo "✅ Added domain: $domain"
    else
        echo "❌ Failed to add domain: $domain"
    fi
}

remove_domain() {
    local domain="$1"
    local padded_key
    padded_key=$(pad_key "$domain")

    if bpftool map delete pinned "$MAP_PATH" key hex $padded_key > /dev/null 2>&1; then
        echo "🗑️ Removed domain: $domain"
    else
        echo "❌ Failed to remove domain: $domain"
    fi
}

list_domains() {
  bpftool map dump pinned "$MAP_PATH" | awk '
    /key":/  {
      sub(/.*"key": "/, "");
      sub(/",.*/, "");
      print $0;
    }
  '
}

usage() {
    echo "Usage:"
    echo "  $0 add <domain>"
    echo "  $0 del <domain>"
    echo "  $0 list"
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    case "$1" in
        add)
            [[ $# -eq 2 ]] && add_domain "$2" || usage
            ;;
        del)
            [[ $# -eq 2 ]] && remove_domain "$2" || usage
            ;;
        list)
            list_domains
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
