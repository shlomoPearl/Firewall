from scapy.all import Ether, IP, ICMP, TCP, UDP, Raw, sendp
import sys, time

host_mac, src_ip, dport = sys.argv[1], sys.argv[2], int(sys.argv[3])
IFACE, TARGET = "veth-ns", "10.0.0.1"

def eth(case):  # unique, locally-administered source MAC per case
    return Ether(src=f"02:de:ad:be:ef:{case:02x}", dst=host_mac)

def send(frame, keep=None):
    raw = bytes(frame)
    sendp(raw[:keep] if keep else raw, iface=IFACE, verbose=False)
    time.sleep(0.2)

# 0: control, well-formed, same src IP / dport as the malformed cases -> must arrive
send(eth(0)/IP(src=src_ip, dst=TARGET)/TCP(sport=1234, dport=dport)/Raw(load="ok"))
# 2: truncated inside the IP header
send(eth(2)/IP(src=src_ip, dst=TARGET)/ICMP(), keep=24)
# 4: IHL claims 60 bytes
send(eth(4)/IP(src=src_ip, dst=TARGET, ihl=15)/ICMP())
# 5: TCP doff below minimum
send(eth(5)/IP(src=src_ip, dst=TARGET)/TCP(sport=1234, dport=dport, dataofs=1)/Raw(load="test"))
# 6: TCP doff larger than the packet
send(eth(6)/IP(src=src_ip, dst=TARGET)/TCP(sport=1234, dport=dport, dataofs=15)/Raw(load="test"))
# 7: truncated inside the UDP header
send(eth(7)/IP(src=src_ip, dst=TARGET)/UDP(sport=1234, dport=dport)/Raw(load="x"), keep=38)