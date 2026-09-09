from scapy.all import Ether, IP, ICMP, TCP, UDP, Raw, sendp, send
import sys
import time

dst_mac = sys.argv[1]
dst_ip = "10.0.0.1"
iface = "veth-ns"
# packet 1: packet too short for Ethernet header
packet = Ether(dst=dst_mac, type=0x0001)/Raw(load="short")
sendp(packet, iface="veth-ns")
time.sleep(1)
# packet 2: packet too short for IP header
packet = IP(dst="10.0.0.1", len=5)/ICMP()
send(packet, iface="veth-ns")
time.sleep(1)
# packet 3: IHL field indicates a header length that is lower than the actual packet size
packet = IP(dst="10.0.0.1", ihl=6)/ICMP()
send(packet, iface="veth-ns")
time.sleep(1)
# packet 4: iph + iph_len exceeds the valid packet size
packet = IP(dst="10.0.0.1", len=1000)/ICMP()
send(packet, iface="veth-ns")
time.sleep(1)
# packet 5: TCP header length exceeds the valid packet size
packet = IP(dst="10.0.0.1")/TCP(sport=1234, dport=9999, dataofs=1)/Raw(load="test")
send(packet, iface="veth-ns")
time.sleep(1)
# packet 6 : tcp + tcp_len exceeds the valid packet size
packet = IP(dst="10.0.0.1")/TCP(sport=1234, dport=9999, dataofs=15)/Raw(load="test")
send(packet, iface="veth-ns")
time.sleep(1)
# packet 7: UDP header length exceeds the valid packet size
packet = IP(dst="10.0.0.1")/UDP(sport=1234, dport=9999, len=1000)/Raw(load="test")
send(packet, iface="veth-ns")
