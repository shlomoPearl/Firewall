RULES_FILE="rules.json"
BLACK_PORT=9999
ALLOWED_PORT=9090
HOST_IP=10.0.0.1
BLACK_IP=10.0.0.2
ALLOWED_IP=10.0.0.3

setup_netns() {
    # Create an isolated network namespace
    sudo ip netns add fw-test
    
    # Create a veth pair - a virtual "cable" with two ends
    sudo ip link add veth-host type veth peer name veth-ns
    
    # Move one end into the namespace
    sudo ip link set veth-ns netns fw-test
    
    # Assign IPs and bring both ends up
    sudo ip addr add "$HOST_IP"/24 dev veth-host
    sudo ip link set veth-host up

    sudo ip netns exec fw-test ip addr add "$BLACK_IP"/24 dev veth-ns # blocked ip
    sudo ip netns exec fw-test ip addr add "$ALLOWED_IP"/24 dev veth-ns # allowed ip
    sudo ip netns exec fw-test ip link set veth-ns up
    sudo ip netns exec fw-test ip link set lo up
}

cleanup_netns() {
    # Delete the veth pair and the network namespace
    sudo ip netns del fw-test
    sudo ip link del veth-host 2>/dev/null  # veth-ns is destroyed automatically with it
    rm -- *.pcap
}

start_firewall() {
    make -C .. all
    sudo ./firewall veth-host &
}

stop_firewall() {
    sudo pkill "-$1" -f firewall 
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

check_drop() {
    if [ "$1" -eq 0 ]; then
        echo "$2"
        return 1
    else
        echo "$3"
        return 0  
    fi
}

test_drop_ip() {
    success=0
    # test 1: ip drop (also tests default drop policy)
    sudo ip netns exec fw-test ping -I $BLACK_IP -c 1 -W 1 $HOST_IP 
    check_drop $? "Ping from veth-host succeeded, but it should have been blocked" "Ping from veth-host failed as expected"
    ((success +=$?))  
    # test 2: tcp ip drop
    nc -l -p $BLACK_PORT &
    sleep 1  # Give nc a moment to start listening
    sudo ip netns exec fw-test nc -s $BLACK_IP $HOST_IP $ALLOWED_PORT
    check_drop $? "Connection to $HOST_IP:$ALLOWED_PORT succeeded, but it should have been blocked" "Connection to $HOST_IP:$ALLOWED_PORT failed as expected"
    ((success += $?))  
    # test 3: udp ip drop
    sudo ip netns exec fw-test nc -s $BLACK_IP -u $HOST_IP $ALLOWED_PORT
    check_drop $? "Connection to $HOST_IP:$ALLOWED_PORT succeeded, but it should have been blocked" "Connection to $HOST_IP:$ALLOWED_PORT failed as expected"
    ((success += $?))  
    return "$success"
}

test_drop_port() {
    success=0
    # test 4: tcp port drop
    nc -l -p $BLACK_PORT &
    sleep 1  # Give nc a moment to start listening
    sudo ip netns exec fw-test-port nc -s $ALLOWED_IP $HOST_IP $BLACK_PORT
    check_drop $? "Connection to $HOST_IP:$BLACK_PORT succeeded, but it should have been blocked" "Connection to $HOST_IP:$BLACK_PORT failed as expected"
    ((success += $?))  
    # test 5: udp port drop
    sudo ip netns exec fw-test-port nc -s $ALLOWED_IP -u $HOST_IP $BLACK_PORT
    check_drop $? "Connection to $HOST_IP:$BLACK_PORT succeeded, but it should have been blocked" "Connection to $HOST_IP:$BLACK_PORT failed as expected"
    ((success += $?))  
    return "$success"
}

test_drop_fragment() {
    # test 6: fragmented packet drop
    sudo ip netns exec fw-test-allowed hping3 -c 1 -d 20 --frag $HOST_IP
    check_drop $? "Fragmented packet from veth-host succeeded, but it should have been blocked" "Fragmented packet from veth-host failed as expected"
    return $?
}

check_drop_malformed() {
    HOST_MAC=$(ip link show veth-host | awk '/link\/ether/ {print $2}')
    sudo ip netns exec fw-test tcpdump -i veth-ns -n -w sent.pcap &
    TCPDUMP_PID_NS=$!
    sudo tcpdump -i veth-host -n -w received.pcap &
    TCPDUMP_PID_HOST=$!

    sudo ./malformed_packet.py "$HOST_MAC" "$1" &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    if [[ "$count_recived" -ne 0 && "$count_sent" -le 0 ]]; then
        echo "Malformed packet$1 error - not droped or not send"
        return 1
    else
        echo "Malformed packet$1 droped from veth-host as expected"
        return 0
    fi
    truncate -s 0 recived.pcap
    truncate -s 0 sent.pcap

    sudo kill $TCPDUMP_PID_NS
    sudo kill $TCPDUMP_PID_HOST   
}

test_drop_malformed() {
    # test 7: malformed packet
    success=0
    check_drop_malformed 1
    ((success += "$?"))
    check_drop_malformed 2
    ((success += "$?"))
    check_drop_malformed 4
    ((success += "$?"))
    check_drop_malformed 5
    ((success += "$?"))
    check_drop_malformed 6
    ((success += "$?"))
    check_drop_malformed 7
    ((success += "$?"))
    return "$success"
}

check_pass() {
    if [ "$1" -ne 0 ]; then
        echo "$2"
        return 1
    else
        echo "$3"
    fi

}

test_pass() {
    success=0
    #test 1: ip pass
    sudo ip netns exec fw-test ping -c 1 -W 1 "$HOST_IP" 
    check_pass "$?" "Ping from veth-host unsucceeded, but it should have been pass" "Ping from veth-host unsucceeded, but it should have been pass"
    ((success += "$?"))
    # test 2: tcp pass
    nc -l -p "$ALLOWED_PORT" &
    sleep 1  # Give nc a moment to start listening
    sudo ip netns exec fw-test nc "$HOST_IP" "$ALLOWED_PORT"
    check_pass "$?" "Connection to '$HOST_IP':'$ALLOWED_PORT' TCP unsucceeded, but it should have been pass" "Connection to '$HOST_IP':'$ALLOWED_PORT' TCP pass as expected"
    ((success += "$?"))
    # test 3: udp pass
    sudo ip netns exec fw-test nc -u "$HOST_IP" "$ALLOWED_IP"
    check_pass "$?" "Connection to '$HOST_IP':'$ALLOWED_PORT' UDP unsucceeded, but it should have been pass" "Connection to '$HOST_IP':'$ALLOWED_PORT' UDP pass as expected"
    ((success += "$?"))
    return "$success"
}

test_add_ip_rule() {
    jq '.ip_blacklist += ['"$1"']' "$RULES_FILE" > tmp.json && mv tmp.json "$RULES_FILE" 
    sleep 1
}

test_add_port_rule() {
    jq '.port_blacklist += ['"$1"']' "$RULES_FILE" > tmp.json && mv tmp.json "$RULES_FILE" 
    sleep 1
}

total_test=0
test_pass=0
test_fail=0

check_status() {
    ((total_test += 1))
    if [ "$1" -ne 0 ]; then
        ((test_fail += 1))
        echo "TEST - $2 FAIL"
    else
        ((test_pass += 1))
        echo "TEST - $2 PASS"
    fi
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

    test_drop_ip
    check_status $? "test_drop_ip"

    test_drop_port
    check_status $? "test_drop_port"

    test_drop_fragment
    check_status $? "test_drop_fragment"

    test_drop_malformed
    check_status $? "test_drop_malformed"

    test_pass
    check_status $? "test_pass_filtering"

    summary
    stop_firewall SIGINT
    cleanup_netns
}
 
summary() {
    echo "TOTAL TESTS: $total_test"
    echo "PASSED: $test_pass"
    echo "FAILED: $test_fail"   
    echo "TEST SUMMARY: $test_pass/$total_test tests passed, $test_fail/$total_test tests failed"
    echo "AVG PASS: $(echo "scale=2; $test_pass/$total_test*100" | bc)%"
    echo "AVG FAIL: $(echo "scale=2; $test_fail/$total_test*100" | bc)%"
}

trap cleanup_netns EXIT 