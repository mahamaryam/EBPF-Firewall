#INCOMPLETE!!
#!/bin/bash

port_block() {
    local port=$1
    sudo bpftool map update name port_blocker key $port value 1
}

port_allow() {
    local port=$1
    sudo bpftool map update name port_blocker key $port value 0
}

ip_block() {
    local ip=$1
    # Convert IP to 4 bytes
    IFS='.' read -ra parts <<< "$ip"
    if [ ${#parts[@]} -ne 4 ]; then
        echo "Invalid IP: $ip"
        return 1
    fi
    sudo bpftool map update name blocked_ips key hex ${parts[0]} ${parts[1]} ${parts[2]} ${parts[3]} value 1
}

ip_allow() {
    local ip=$1
    IFS='.' read -ra parts <<< "$ip"
    if [ ${#parts[@]} -ne 4 ]; then
        echo "Invalid IP: $ip"
        return 1
    fi
    sudo bpftool map update name blocked_ips key hex ${parts[0]} ${parts[1]} ${parts[2]} ${parts[3]} value 0
}

protocol_block() {
    local proto=$1
    sudo bpftool map update name black_protocol key $proto value 1
}

protocol_allow() {
    local proto=$1
    sudo bpftool map update name black_protocol key $proto value 0
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
disable_mafw()
{
sudo net detach xdp dev wlo1
#sudo rm /sys/fs/bpf/? yes or no?
}
enable_mafw()
{
#clang ?
#then laod. 2>/dev/null
#sudo net attach xdp id 4 dev wlo1 ----> define interface.
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
        *)
            echo "Unknown command: $cmd"
            echo "Available commands: port_block, port_allow, ip_block, ip_allow, protocol_block, protocol_allow, enable_rpf, disable_rpf, enable_spi, disable_spi, enable_rl, disable_rl"
            return 1
            ;;
    esac
}

main "$@"

