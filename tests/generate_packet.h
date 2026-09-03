#pragma once
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define PACKET_SIZE 64
#define MALFORMED_CHECKS 7
#define DC_IP_S "100.000.1.1"
#define DC_IP_D "100.000.2.2"
#define DC_PORT_S 80
#define DC_PORT_D 443


void create_ipv4_packet(char *packet, __u8 protocol, const char *src_ip, const char *dst_ip,
                                                                  __u16 src_port, __u16 dst_port);

void create_malformed_packets(char *packet);

void create_fragmented_packet(char *packet);

void create_non_ip_packet(char *packet);

void create_non_tcp_udp_packet(char *packet, const char *src_ip, const char *dst_ip);

void create_ipv6_packet(char *packet);