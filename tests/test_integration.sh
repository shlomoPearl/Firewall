RULES_FILE="tests/test_rules.json"
BLACK_PORT=9999
NEW_BLACK_PORT=9091
ALLOWED_PORT=9090
HOST_IP=10.0.0.1
BLACK_IP=10.0.0.2
NEW_BLACK_IP=10.0.0.3
ALLOWED_IP=10.0.0.4

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
    sudo ip netns exec fw-test ip addr add "$NEW_BLACK_IP"/24 dev veth-ns
    sudo ip netns exec fw-test ip link set veth-ns up
    sudo ip netns exec fw-test ip link set lo up
}

cleanup() {
    # Delete the veth pair and the network namespace
    sudo ip netns del fw-test 2>/dev/null
    sudo ip link del veth-host 2>/dev/null  # veth-ns is destroyed automatically with it
    rm -- *.pcap 2>/dev/null
    pkill firewall  
}

start_firewall() {
    sudo ./firewall veth-host test &
    FIREWALL_PID=$!
}

stop_firewall() {
    sudo kill -"$1" "$FIREWALL_PID" 
}

test_attach() {
    echo "Testing attach/detach"
    sleep 0.5
    sudo bpftool prog show name xdp_filter > /dev/null
    return $?
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

test_tcp_conn() {
    local src_ip="$1" dst_ip="$2" port="$3"
    nc -l -p "$port" &
    local listener_pid=$!
    sleep 0.5
    sudo ip netns exec fw-test nc -z -w 1 -s "$src_ip" "$dst_ip" "$port"
    local result=$?
    kill "$listener_pid" 2>/dev/null
    wait "$listener_pid" 2>/dev/null
    return "$result"
}

test_udp_conn() {
    local src_ip="$1" dst_ip="$2" port="$3"
    sudo ip netns exec fw-test tcpdump -i veth-ns -n -w udp_sent.pcap > /dev/null 2>&1 &
    local tcpdump_ns=$!
    sudo tcpdump -i veth-host -n "udp and port $port" -w udp_received.pcap > /dev/null 2>&1 &
    local tcpdump_host=$!
    sleep 0.5
    echo "probe" | sudo ip netns exec fw-test nc -u -w 1 -s "$src_ip" "$dst_ip" "$port"
    sleep 0.5
    sudo kill "$tcpdump_ns" "$tcpdump_host" 2>/dev/null
    wait "$tcpdump_ns" "$tcpdump_host" 2>/dev/null

    local sent received
    sent=$(tcpdump -r udp_sent.pcap -n 2>/dev/null | wc -l)
    received=$(tcpdump -r udp_received.pcap -n 2>/dev/null | wc -l)
    > udp_sent.pcap
    > udp_received.pcap 
    if [[ "$sent" -gt 0 && "$received" -eq 0 ]]; then
	return 1 # dropped
    else
	return 0 # passed
    fi
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
    local src_ip="$1"
    local success=0
    echo "test: ip drop ICMP"
    sudo ip netns exec fw-test ping -I "$src_ip" -c 1 -W 1 $HOST_IP > /dev/null 2>&1
    check_drop $? "Ping from $src_ip succeeded, but it should have been blocked" "Ping from $src_ip blockeed as expected"
    ((success +=$?))  

    echo "test: ip drop - TCP"
    test_tcp_conn "$src_ip" "$HOST_IP" "$ALLOWED_PORT"
    check_drop $? "TCP from $src_ip succeeded, but it should have been blocked" "TCP from $src_ip blocked as expected"
    ((success += $?))  

    echo "test: ip drop - UDP"
    test_udp_conn "$src_ip" "$HOST_IP" "$ALLOWED_PORT"
    check_drop $? "UDP from $src_ip succeeded, but it should have been blocked" "UDP from $src_ip blocked as expected"
    ((success += $?))
  
    return "$success"
}

test_drop_port() {
    local port="$1"
    local success=0

    echo test: port drop - TCP
    test_tcp_conn "$ALLOWED_IP" "$HOST_IP" "$port"
    check_drop $? "TCP to port $port succeeded, should have been blocked" "TCP to port $port blocked as expected"
    ((success += $?))  

    echo test: port drop - UDP
    test_udp_conn "$ALLOWED_IP" "$HOST_IP" "$port"
    check_drop $? "UDP to port $port succeeded, should have been blocked" "UDP to port $port blocked as expected"
    ((success += $?))  

    return "$success"
}

test_drop_fragment() {
    # test 6: fragmented packet drop
    sudo ip netns exec fw-test hping3 -c 1 -d 20 --frag $HOST_IP
    check_drop $? "Fragmented packet from veth-host succeeded, but it should have been blocked" "Fragmented packet from veth-host failed as expected"
    return $?
}

check_drop_malformed() {
    HOST_MAC=$(ip link show veth-host | awk '/link\/ether/ {print $2}')
    sudo ip netns exec fw-test tcpdump -i veth-ns -n -w sent.pcap > /dev/null 2>&1 & 
    TCPDUMP_PID_NS=$!
    sudo tcpdump -i veth-host -n -w received.pcap > /dev/null 2>&1 & 
    TCPDUMP_PID_HOST=$!

    sudo python3 tests/malformed_packet.py "$HOST_MAC" "$1" &
    sleep 0.5
    count_recived=$(tcpdump -r received.pcap -n 2>/dev/null | wc -l)
    count_sent=$(tcpdump -r sent.pcap -n 2>/dev/null | wc -l)
    success=0
    if [[ "$count_recived" -ne 0 && "$count_sent" -le 0 ]]; then
        echo "Malformed packet$1 error - not droped or not send"
        success=1
    else
        echo "Malformed packet$1 droped from veth-host as expected"
    fi
    sudo kill "$TCPDUMP_PID_HOST" "$TCPDUMP_PID_NS" 2>/dev/null
    wait "$TCPDUMP_PID_HOST" "$TCPDUMP_PID_NS" 2>/dev/null
    > sent.pcap
    > received.pcap
    return "$success"
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

test_packet_pass() {
    local src_ip="$1" port="$2"
    local success=0
    echo "test: pass ICMP"
    sudo ip netns exec fw-test ping -c 1 -W 1 -I "$src_ip" "$HOST_IP" > /dev/null 2>&1
    check_pass "$?" "Ping from $src_ip failed, should have passed" "Ping from $src_ip passed as expected"
    ((success += "$?"))

    echo "test: pass - TCP"
    test_tcp_conn "$src_ip" "$HOST_IP" "$port"
    check_pass "$?" "TCP from $src_ip:$port falied, should have passed" "TCP from $src_ip:$port passed as expected"
    ((success += "$?"))

    echo "test: pass - UDP"
    test_udp_conn "$src_ip" "$HOST_IP" "$port"
    check_pass "$?" "UDP from $src_ip:$port failed shuold have passed" "UDP from $src_ip:$port passed as expected"
    ((success += "$?"))

    return "$success"
}

test_add_ip_rule() {
    jq --arg ips "$1" '.ip_blacklist += [$ips]' "$RULES_FILE" > tmp.json && mv tmp.json "$RULES_FILE" 
    sleep 1
    test_drop_ip "$1"
    return "$?"
}

test_remove_ip_rule() {
    jq --arg ips "$1" '.ip_blacklist -= [$ips]' "$RULES_FILE" > tmp.json && mv tmp.json "$RULES_FILE" 
    sleep 1
    test_packet_pass "$1" "$ALLOWED_PORT"
}

test_add_port_rule() {
    jq --arg ports "$1" '.port_blacklist += [$ports]' "$RULES_FILE" > tmp.json && mv tmp.json "$RULES_FILE" 
    sleep 1
    test_drop_port "$1"
    return "$?"
}

test_remove_port_rule() {
    jq --arg ports "$1" '.port_blacklist -= [$ports]' "$RULES_FILE" > tmp.json && mv tmp.json "$RULES_FILE" 
    sleep 1
    test_packet_pass "$ALLOWED_IP" "$1"
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

    test_drop_ip "$BLACK_IP"
    check_status $? "test_drop_ip"

    test_drop_port "$BLACK_PORT"
    check_status $? "test_drop_port"

    test_drop_fragment
    check_status $? "test_drop_fragment"

    test_drop_malformed
    check_status $? "test_drop_malformed"

    test_packet_pass "$ALLOWED_IP" "$ALLOWED_PORT"
    check_status $? "test_packet_pass_filtering"

    test_add_ip_rule "$NEW_BLACK_IP"
    check_status $? test_add_ip_rule

    test_remove_ip_rule "$NEW_BLACK_IP"
    check_status $? test_remove_ip_rule

    test_add_port_rule "$NEW_BLACK_PORT"
    check_status $? test_add_port_rule

    test_remove_port_rule "$NEW_BLACK_PORT"
    check_status $? test_remove_port_rule

    stop_firewall SIGINT
}
 
summary() {
    echo "TOTAL TESTS: $total_test"
    echo "PASSED: $test_pass"
    echo "FAILED: $test_fail"   
    echo "TEST SUMMARY: $test_pass/$total_test tests passed, $test_fail/$total_test tests failed"
    echo "AVG PASS: $(echo "scale=2; $test_pass/$total_test*100" | bc)%"
    echo "AVG FAIL: $(echo "scale=2; $test_fail/$total_test*100" | bc)%"
}

cleanup
test_runner
summary
trap cleanup EXIT 
