setup_netns() {
    # Create an isolated network namespace
    sudo ip netns add fw-test
    
    # Create a veth pair - a virtual "cable" with two ends
    sudo ip link add veth-host type veth peer name veth-ns
    
    # Move one end into the namespace
    sudo ip link set veth-ns netns fw-test
    
    # Assign IPs and bring both ends up
    sudo ip addr add 10.0.0.1/24 dev veth-host
    sudo ip link set veth-host up

    sudo ip netns exec fw-test ip addr add 10.0.0.2/24 dev veth-ns
    sudo ip netns exec fw-test ip addr add 10.0.0.3/24 dev veth-ns
    sudo ip netns exec fw-test ip addr add 10.0.0.4/24 dev veth-ns
    sudo ip netns exec fw-test ip link set veth-ns up
    sudo ip netns exec fw-test ip link set lo up
}

cleanup_netns() {
    # Delete the veth pair and the network namespace
    sudo ip netns del fw-test
    sudo ip link del veth-host 2>/dev/null  # veth-ns is destroyed automatically with it
    rm *.pcap
}

start_firewall() {
    make -C .. all
    sudo ./firewall veth-host &
}

stop_firewall() {
    sudo pkill -$1 -f firewall 
}

test_attach() {
    echo "Testing attach/detach"
    attached=$(sudo ip -d link show veth-host | grep "xdp_filter")
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
    test_attach
    attached=$?
    if [ $attached -eq 0 ]; then
        echo "XDP program is STILL attached after SIGINT"
        return 1
    fi
    start_firewall
    sleep 1
    test_attach
    return $?
}

test_SIGTERM_2_attached() {
    echo "Testing SIGTERM handling"
    stop_firewall SIGTERM  
    sleep 1  # Give it a moment to clean up
    test_attach
    attached=$?
    if [ $attached -eq 0 ]; then
        echo "XDP program is STILL attached after SIGTERM"
        return 1
    fi  
    start_firewall
    sleep 1
    test_attach
    return $?
}



test_drop_filtering() {
    echo "Testing packet filtering"
    # test 1: ip drop (also tests default drop policy)
    sudo ip netns exec fw-test ping -I 10.0.0.2 -c 1 -W 1 10.0.0.1 
    ping_status=$?
    if [ $ping_status -eq 0 ]; then
        echo "Ping from veth-host succeeded, but it should have been blocked"
        return 1
    else
        echo "Ping from veth-host failed as expected"
    fi  
    # test 2: tcp ip drop
    nc -l -p 9090 &
    sleep 1  # Give nc a moment to start listening
    sudo ip netns exec fw-test nc -s 10.0.0.2 10.0.0.1 9090
    nc_status=$?
    if [ $nc_status -eq 0 ]; then
        echo "Connection to 10.0.0.1:9090  succeeded, but it should have been blocked"
        return 1
    else
        echo "Connection to 10.0.0.1:9090 failed as expected"
    fi
    # test 3: udp ip drop
    sudo ip netns exec fw-test nc -s 10.0.0.2 -u 10.0.0.1 9090
    nc_status=$?
    if [ $nc_status -eq 0 ]; then
        echo "Connection to 10.0.0.1:9090  succeeded, but it should have been blocked"
        return 1
    else
        echo "Connection to 10.0.0.1:9090 failed as expected"
    fi
    # test 4: tcp port drop
    nc -l -p 9999 &
    sleep 1  # Give nc a moment to start listening
    sudo ip netns exec fw-test-port nc -s 10.0.0.3 10.0.0.1 9999
    nc_status=$?
    if [ $nc_status -eq 0 ]; then
        echo "Connection to 10.0.0.1:9999 succeeded, but it should have been blocked"
        return 1
    else
        echo "Connection to 10.0.0.1:9999 failed as expected"
    fi
    # test 5: udp port drop
    sudo ip netns exec fw-test-port nc -s 10.0.0.3 -u 10.0.0.1 9999
    nc_status=$?
    if [ $nc_status -eq 0 ]; then
        echo "Connection to 10.0.0.1:9999 succeeded, but it should have been blocked"
        return 1
    else
        echo "Connection to 10.0.0.1:9999 failed as expected"
    fi
    # test 6: fragmented packet drop
    sudo ip netns exec fw-test-allowed hping3 -c 1 -d 20 --frag 10.0.0.1
    fragmented_status=$?
    if [ $fragmented_status -eq 0 ]; then
        echo "Fragmented packet from veth-host succeeded, but it should have been blocked"
        return 1
    else
        echo "Fragmented packet from veth-host failed as expected"
    fi
    # test 7: malformed packet - TO-DO
    HOST_MAC=$(ip link show veth-host | awk '/link\/ether/ {print $2}')
    sudo ip netns exec fw-test tcpdump -i veth-ns -n -w sent.pcap &
    TCPDUMP_PID_NS=$!
    sudo tcpdump -i veth-host -n -w received.pcap &
    TCPDUMP_PID_HOST=$!

    sudo ./malformed_packet.py $HOST_MAC 1 &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    if [ $count_recived -ne 0 and $count_sent -le 0 ]; then
        echo "Malformed packet1 error - not droped or not send"
        return 1
    else
        echo "Malformed packet1 droped from veth-host as expected"
    fi
    truncate -s 0 recived.pcap
    truncate -s 0 sent.pcap

    sudo ./malformed_packet.py $HOST_MAC 2 &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    if [ $count_recived -ne 0 and $count_sent -le 0 ]; then
        echo "Malformed packet1 error - not droped or not send"
        return 1
    else
        echo "Malformed packet1 droped from veth-host as expected"
    fi
    truncate -s 0 recived.pcap
    truncate -s 0 sent.pcap

    sudo ./malformed_packet.py $HOST_MAC 4 &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    if [ $count_recived -ne 0 and $count_sent -le 0 ]; then
        echo "Malformed packet1 error - not droped or not send"
        return 1
    else
        echo "Malformed packet1 droped from veth-host as expected"
    fi
    truncate -s 0 recived.pcap
    truncate -s 0 sent.pcap

    sudo ./malformed_packet.py $HOST_MAC 5 &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    if [ $count_recived -ne 0 and $count_sent -le 0 ]; then
        echo "Malformed packet1 error - not droped or not send"
        return 1
    else
        echo "Malformed packet1 droped from veth-host as expected"
    fi
    truncate -s 0 recived.pcap
    truncate -s 0 sent.pcap

    sudo ./malformed_packet.py $HOST_MAC 6 &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    if [ $count_recived -ne 0 and $count_sent -le 0 ]; then
        echo "Malformed packet1 error - not droped or not send"
        return 1
    else
        echo "Malformed packet1 droped from veth-host as expected"
    fi
    truncate -s 0 recived.pcap
    truncate -s 0 sent.pcap

    sudo ./malformed_packet.py $HOST_MAC 7 &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    if [ $count_recived -ne 0 and $count_sent -le 0 ]; then
        echo "Malformed packet1 error - not droped or not send"
        return 1
    else
        echo "Malformed packet1 droped from veth-host as expected"
    fi
    truncate -s 0 recived.pcap
    truncate -s 0 sent.pcap

    sudo kill $TCPDUMP_PID_NS
    sudo kill $TCPDUMP_PID_HOST   
    cleanup_netns 
}



test_pass_filtering() {
    #test 1: ip pass
    sudo ip netns exec fw-test ping -c 1 -W 1 10.0.0.1 
    ping_status=$?
    if [ $ping_status -eq 1 ]; then
        echo "Ping from veth-host unsucceeded, but it should have been pass"
        return 1
    else
        echo "Ping from veth-host pass as expected"
    fi
    # test 2: tcp pass
    nc -l -p 9999 &
    sleep 1  # Give nc a moment to start listening
    sudo ip netns exec fw-test nc 10.0.0.1 9999
    nc_status=$?
    if [ $nc_status -ne 0 ]; then
        echo "Connection to 10.0.0.1:9999 TCP unsucceeded, but it should have been pass"
        return 1
    else
        echo "Connection to 10.0.0.1:9999 TCP pass as expected"
    fi
    # test 2: udp pass
    sudo ip netns exec fw-test nc -u 10.0.0.1 9999
    nc_status=$?
    if [ $nc_status -ne 0 ]; then
        echo "Connection to 10.0.0.1:9999 UDP unsucceeded, but it should have been pass"
        return 1
    else
        echo "Connection to 10.0.0.1:9999 UDP pass as expected"
    fi
}

test_add_rules() {

}

total_test=0
test_pass=0
test_fail=0

check_status() {
    ((total_test += 1))
    if [ $1 -ne 0 ]; then
        ((test_fail += 1))
        echo "TEST - $2 FAIL"
    else
        ((test_pass += 1))
        echo "TEST - $2 PASS"
    fi
}

summary() {
    echo "TOTAL TESTS: $total_test"
    echo "PASSED: $test_pass"
    echo "FAILED: $test_fail"   
    echo "TEST SUMMARY: $test_pass/$total_test tests passed, $test_fail/$total_test tests failed"
    echo "AVG PASS: $(echo "scale=2; $test_pass/$total_test*100" | bc)%"
    echo "AVG FAIL: $(echo "scale=2; $test_fail/$total_test*100" | bc)%"
}

test_runner() {
    setup_netns
    start_firewall
    test_attach
    check_status $? "test_attach"

    test_SIGINT_2_attached
    check_status $? "test_SIGINT"

    test_SIGTERM_2_attached
    check_status $? "test_SIGTERM"

    test_pass
    check_status $? "test_pass"

    test_drop_filtering
    check_status $? "test_drop_filtering"

    stop_firewall
    cleanup_netns
}
 
trap cleanup_netns EXIT 