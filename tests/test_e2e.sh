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
    sudo pkill -f ./firewall
}
 
trap cleanup_netns EXIT 