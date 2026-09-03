#include "generate_packet.h"

void create_ipv4_packet(char *packet, __u8 protocol, const char *src_ip, const char *dst_ip, __u16 src_port, __u16 dst_port) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    memset(packet, 0, PACKET_SIZE);
    
    eth->h_proto = htons(ETH_P_IP);
    
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(PACKET_SIZE - sizeof(struct ethhdr));
    ip->protocol = protocol;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    
    if (protocol == IPPROTO_TCP){
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        tcp->doff = 5;
        tcp->source = htons(src_port);
        tcp->dest = htons(dst_port);
    }
    else if (protocol == IPPROTO_UDP){
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        udp->source = htons(src_port);
        udp->dest = htons(dst_port);    
    }
}

void create_malformed_packets(char *packet) {
    memset(packet, 0, PACKET_SIZE * MALFORMED_CHECKS); 
    // packet 1: packet too short for Ethernet header
    struct ethhdr *eth = (struct ethhdr *)packet;
    eth->h_proto = htons(ETH_P_IP);
    // packet 2: packet too short for IP header
    *eth = (struct ethhdr *)packet + PACKET_SIZE;
    eth->h_proto = htons(ETH_P_IP);
    struct iphdr *ip = (struct iphdr *)(packet + PACKET_SIZE + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(PACKET_SIZE - sizeof(struct ethhdr));
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(DC_IP_S);
    ip->daddr = inet_addr(DC_IP_D);
    // packet 3: IHL field indicates a header length that is lower than the actual packet size
    *eth = (struct ethhdr *)packet + 2 * PACKET_SIZE;
    eth->h_proto = htons(ETH_P_IP);
    struct iphdr *ip2 = (struct iphdr *)(packet + 2 * PACKET_SIZE + sizeof(struct ethhdr));
    ip2->version = 4;
    ip2->ihl = 6; // IHL indicates 40 bytes, but the actual packet size is only 64 bytes
    ip2->tot_len = htons(PACKET_SIZE - sizeof(struct ethhdr));
    ip2->protocol = IPPROTO_TCP;
    ip2->saddr = inet_addr(DC_IP_S);
    ip2->daddr = inet_addr(DC_IP_D);
    // packet 4: iph + iph_len exceeds the valid packet size
    *eth = (struct ethhdr *)packet + 3 * PACKET_SIZE;
    eth->h_proto = htons(ETH_P_IP);
    struct iphdr *ip3 = (struct iphdr *)(packet + 3 * PACKET_SIZE + sizeof(struct ethhdr));
    ip3->version = 4;
    ip3->ihl = 13; // IHL indicates 40 bytes, but the actual packet size is only 64 bytes
    ip3->tot_len = htons(PACKET_SIZE - sizeof(struct ethhdr));
    ip3->protocol = IPPROTO_TCP;
    ip3->saddr = inet_addr(DC_IP_S);
    ip3->daddr = inet_addr(DC_IP_D);
    // packet 5: TCP header length exceeds the valid packet size
    create_ipv4_packet(packet + 4 * PACKET_SIZE, IPPROTO_TCP, DC_IP_S, DC_IP_D, 80, 443);
    struct tcphdr *tcp = (struct tcphdr *)(packet + 4 * PACKET_SIZE + sizeof(struct ethhdr) + sizeof(struct iphdr));
    tcp->doff = 1; // TCP header length indicates 80 bytes, but the actual packet size is only 64 bytes
    // packet 6: tcp + tcp_len exceeds the valid packet size
    create_ipv4_packet(packet + 5 * PACKET_SIZE, IPPROTO_TCP, DC_IP_S, DC_IP_D, 80, 443);
    struct tcphdr *tcp2 = (struct tcphdr *)(packet + 5 * PACKET_SIZE + sizeof(struct ethhdr) + sizeof(struct iphdr));
    tcp2->doff = 20; // TCP header length indicates 80 bytes, but the actual packet size is only 64 bytes
    // packet 7: UDP header exceeds the valid packet size
    create_ipv4_packet(packet + 6 * PACKET_SIZE, IPPROTO_UDP, DC_IP_S, DC_IP_D, 80, 443);
    struct udphdr *udp = (struct udphdr *)(packet + 6 * PACKET_SIZE + sizeof(struct ethhdr) + sizeof(struct iphdr));

}

void create_fragmented_packet(char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    memset(packet, 0, PACKET_SIZE);
    eth->h_proto = htons(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(PACKET_SIZE - sizeof(struct ethhdr));
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(DC_IP_S);
    ip->daddr = inet_addr(DC_IP_D);
    // Set the fragment offset to indicate that this is a fragmented packet
    ip->frag_off = htons(0x2000); // More fragments flag set
}

void create_non_ip_packet(char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    memset(packet, 0, PACKET_SIZE);
    eth->h_proto = htons(ETH_P_ARP); // ARP
}

void create_non_tcp_udp_packet(char *packet, const char *src_ip, const char *dst_ip) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    memset(packet, 0, PACKET_SIZE);
    eth->h_proto = htons(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(PACKET_SIZE - sizeof(struct ethhdr));
    ip->protocol = IPPROTO_ICMP; // ICMP 
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
}

void create_ipv6_packet(char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    memset(packet, 0, PACKET_SIZE);
    eth->h_proto = htons(ETH_P_IPV6); // IPv6
}