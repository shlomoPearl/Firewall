setup_netns() {
    # Create an isolated network namespace
    sudo ip netns add fw-test

    # Create a veth pair — a virtual "cable" with two ends
    sudo ip link add veth-host type veth peer name veth-ns

    # Move one end into the namespace
    sudo ip link set veth-ns netns fw-test

    # Assign IPs and bring both ends up
    sudo ip addr add 10.0.0.1/24 dev veth-host
    sudo ip link set veth-host up
    sudo ip netns exec fw-test ip addr add 10.0.0.2/24 dev veth-ns
    sudo ip netns exec fw-test ip link set veth-ns up
    sudo ip netns exec fw-test ip link set lo up
}

cleanup_netns() {
    # Delete the veth pair and the network namespace
    sudo ip netns del fw-test
    sudo ip link del veth-host 2>/dev/null  # veth-ns is destroyed automatically with it
}

start_firewall() {
    make -C .. -f all
    sudo ./firewall &
}

stop_firewall() {
    sudo pkill -$1 -f firewall
}

test_attach() {
    echo "Testing attach/detach"
    attached=$(sudo ip link show veth-host | grep "xdp_filter")
    if [ -n "$attached" ]; then
        return 0
    else
        echo "XDP program is NOT attached to veth-host"
        return 1
    fi
}

test_SIGINT_2_attached() {
    echo "Testing SIGINT handling"
    stop_firewall SIGINT
    sleep 1  # Give it a moment to clean up
    attached=$(sudo ip link show veth-host | grep "xdp_filter")
    if [ -z "$attached" ]; then
        return 0
    else
        echo "XDP program is STILL attached after SIGINT"
        return 1
    fi
    start_firewall
    test_attach
    attached=$?
    if [ $attached -ne 0 ]; then
        echo "XDP program is NOT attached after SIGINT restart"
        return 1
    fi
    return 0
}

test_SIGTERM_2_attached() {
    echo "Testing SIGTERM handling"
    stop_firewall SIGTERM  
    sleep 1  # Give it a moment to clean up
    attached=$(sudo ip link show veth-host | grep "xdp_filter")
    if [ -z "$attached" ]; then
        return 0
    else
        echo "XDP program is STILL attached after SIGTERM"
        return 1
    fi  
    start_firewall
    test_attach
    attached=$?
    if [ $attached -ne 0 ]; then
        echo "XDP program is NOT attached after SIGTERM restart"
        return 1
    fi
    return 0
}


 
trap cleanup_netns EXIT 