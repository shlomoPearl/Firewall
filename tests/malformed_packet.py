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



"""

from scapy.all import Ether, IP, ICMP, TCP, UDP, Raw, sendp
import sys, time

dst_mac = sys.argv[1]
IFACE = "veth-ns"
TARGET = "10.0.0.1"

def send_truncated(pkt, keep_bytes, label):
    raw = bytes(pkt)[:keep_bytes]
    print(pkt[IP].src)
    print(f"{label}: sending {len(raw)} raw bytes", flush=True)
    sendp(Raw(load=raw), iface=IFACE, verbose=False)
    time.sleep(1)

pkt_num = int(sys.argv[2])

match pkt_num:
    case 1:
        # packet 1: too short for Ethernet header — genuine truncation, below 14 bytes
        send_truncated(Ether(dst=dst_mac)/IP(dst=TARGET)/ICMP(), 10, "too short for Ethernet")
    case 2:
        # packet 2: too short for IP header — genuine truncation, 14 + partial IP
        send_truncated(Ether(dst=dst_mac)/IP(dst=TARGET)/ICMP(), 24, "too short for IP header")
    case 4:
        # packet 4: IHL claims more than the real packet holds — field-based, no truncation needed
        pkt = Ether(dst=dst_mac)/IP(dst=TARGET, ihl=15)/ICMP()
        print(pkt[IP].src)
        sendp(pkt, iface=IFACE); time.sleep(1)
    case 5:
        # packet 5: TCP doff too small (sanity check)
        pkt = Ether(dst=dst_mac)/IP(dst=TARGET)/TCP(sport=1234, dport=9999, dataofs=1)/Raw(load="test")
        print(pkt[IP].src)
        sendp(pkt, iface=IFACE); time.sleep(1)
    case 6:
        # packet 6: TCP doff exceeds real size (bounds check)
        pkt = Ether(dst=dst_mac)/IP(dst=TARGET)/TCP(sport=1234, dport=9999, dataofs=15)/Raw(load="test")
        sendp(pkt, iface=IFACE); time.sleep(1)
    case 7:
        # packet 7: too short for UDP header — genuine truncation
        send_truncated(Ether(dst=dst_mac)/IP(dst=TARGET)/UDP(sport=1234, dport=9999)/Raw(load="x"), 38, "too short for UDP header")

"""
