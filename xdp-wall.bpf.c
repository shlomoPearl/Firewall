#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // Key type: source IP address
    __type(value, bool);  // Value type: boolean (1 for allowed, 0 for blocked)
} ip_blacklist  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  // Key type: source port
    __type(value, bool);  // Value type: boolean (1 for allowed, 0 for blocked)
} port_blacklist  SEC(".maps");

static bool is_tcp_udp(struct iphdr *ip){
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP){
        return false;
    }  
    return true;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    // Pointers to packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        return XDP_PASS;
    }
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return XDP_PASS;
    }
        
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end){
        return XDP_PASS;
    }

    if (!is_tcp_udp(ip)) {
        return XDP_PASS;
    }
    
    // Calculate IP header length
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    // Ensure IP header is within packet bounds
    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u16 src_port;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        __u32 tcp_header_bytes = tcp->doff * 4;
        if (tcp_header_bytes < sizeof(*tcp) || (void *)tcp + tcp_header_bytes > data_end) {
            return XDP_PASS;
        }

        src_port = bpf_ntohs(tcp->source); 
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((unsigned char *)ip + ip_hdr_len);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udp->source);
    } else {
        return XDP_PASS;
    }
    
    bool *ip_rule = bpf_map_lookup_elem(&ip_blacklist, &src_ip);
    bool *port_rule = bpf_map_lookup_elem(&port_blacklist, &src_port);
    if ((ip_rule && *ip_rule) || (port_rule && *port_rule)) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
