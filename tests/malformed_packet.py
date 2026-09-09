from scapy.all import Ether, IP, ICMP, TCP, UDP, Raw, sendp
import sys, time

dst_mac = sys.argv[1]
IFACE = "veth-ns"
TARGET = "10.0.0.1"

def send_truncated(pkt, keep_bytes, label):
    raw = bytes(pkt)[:keep_bytes]
    print(f"{label}: sending {len(raw)} raw bytes")
    sendp(raw, iface=IFACE)
    time.sleep(1)

pkt_num = sys.argv[2]

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
        sendp(pkt, iface=IFACE); time.sleep(1)
    case 5:
        # packet 5: TCP doff too small (sanity check)
        pkt = Ether(dst=dst_mac)/IP(dst=TARGET)/TCP(sport=1234, dport=9999, dataofs=1)/Raw(load="test")
        sendp(pkt, iface=IFACE); time.sleep(1)
    case 6:
        # packet 6: TCP doff exceeds real size (bounds check)
        pkt = Ether(dst=dst_mac)/IP(dst=TARGET)/TCP(sport=1234, dport=9999, dataofs=15)/Raw(load="test")
        sendp(pkt, iface=IFACE); time.sleep(1)
    case 7:
        # packet 7: too short for UDP header — genuine truncation
        send_truncated(Ether(dst=dst_mac)/IP(dst=TARGET)/UDP(sport=1234, dport=9999)/Raw(load="x"), 38, "too short for UDP header")