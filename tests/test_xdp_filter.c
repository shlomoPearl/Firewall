#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../lib/unity.h"
#include "generate_packet.h"

#define PACKET_SIZE 64
#define BLACK_IP "192.192.192.192"
#define BLACK_PORT 65000
#define ALLOWED_IP "192.168.1.1"
#define ALLOWED_PORT 65001
#define DST_IP "127.0.0.1"
#define SRC_PORT 80

static int prog_fd;
static char packet[PACKET_SIZE];
static char malformed_packets[PACKET_SIZE * MALFORMED_CHECKS];
static char fragmented_packet[PACKET_SIZE];
static char pass_packet[PACKET_SIZE];


void setUp(void) {
    // This function is called before each test case
    
}

void tearDown(void) {
    // This function is called after each test case
}

int run_opts_out(char * packet, int packet_size){
    __u32 retval = 0;
    int err = bpf_prog_test_run(prog_fd, 1, packet, packet_size,
                                NULL, 0, &retval, NULL);
    if (err){
        fprintf(stderr, "Failed to run test\n");
        return err;
    }
    return retval;
}

void test_expect_drop(void) {
    create_ipv4_packet(packet, IPPROTO_TCP, BLACK_IP, DST_IP, SRC_PORT, ALLOWED_PORT);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, run_opts_out(packet, PACKET_SIZE));
    
    create_ipv4_packet(packet, IPPROTO_UDP, BLACK_IP, DST_IP, SRC_PORT, ALLOWED_PORT);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, run_opts_out(packet, PACKET_SIZE));
    
    create_ipv4_packet(packet, IPPROTO_TCP, ALLOWED_IP, DST_IP, SRC_PORT, BLACK_PORT);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, run_opts_out(packet, PACKET_SIZE));
    
    create_ipv4_packet(packet, IPPROTO_UDP, ALLOWED_IP, DST_IP, SRC_PORT, BLACK_PORT);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, run_opts_out(packet, PACKET_SIZE));
    
    create_non_tcp_udp_packet(packet, BLACK_IP, DST_IP);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, run_opts_out(packet, PACKET_SIZE));
    
    create_malformed_packets(malformed_packets);
    for (int i = 0; i < MALFORMED_CHECKS; i++) {
        int packet_size = PACKET_SIZE;
        if (i == 0) {
            packet_size = 10; // Packet too short for Ethernet header
        } else if (i == 6) {
            packet_size = 14 + 20 + 4; // Packet too short for UDP header
        }
        TEST_ASSERT_EQUAL_INT(XDP_DROP, run_opts_out(malformed_packets + PACKET_SIZE * i, packet_size));
    }

    create_fragmented_packet(fragmented_packet);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, run_opts_out(fragmented_packet, PACKET_SIZE));
}

void test_expect_pass(void) {
    // NOT blacklisted IP or port:
    create_ipv4_packet(pass_packet, IPPROTO_TCP, ALLOWED_IP, DST_IP, SRC_PORT, ALLOWED_PORT);
    TEST_ASSERT_EQUAL_INT(XDP_PASS, run_opts_out(pass_packet, PACKET_SIZE));

    create_ipv4_packet(pass_packet, IPPROTO_UDP, ALLOWED_IP, DST_IP, SRC_PORT, ALLOWED_PORT);
    TEST_ASSERT_EQUAL_INT(XDP_PASS, run_opts_out(pass_packet, PACKET_SIZE));

    // NOT TCP or UDP:
    create_non_tcp_udp_packet(pass_packet, ALLOWED_IP, DST_IP);
    TEST_ASSERT_EQUAL_INT(XDP_PASS, run_opts_out(pass_packet, PACKET_SIZE));

    // Not IP:
    create_non_ip_packet(pass_packet);
    TEST_ASSERT_EQUAL_INT(XDP_PASS, run_opts_out(pass_packet, PACKET_SIZE));

    // IPv6 packet:
    create_ipv6_packet(pass_packet);
    TEST_ASSERT_EQUAL_INT(XDP_PASS, run_opts_out(pass_packet, PACKET_SIZE));
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_xdp_object>\n", argv[0]);
        return 1;
    }
    
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *ip_map = bpf_object__find_map_by_name(obj, "ip_blacklist");
    if (!ip_map) {
        fprintf(stderr, "Failed to find ip_blacklist map\n");
        bpf_object__close(obj);
        return 1;
    }
    struct bpf_map *port_map = bpf_object__find_map_by_name(obj, "port_blacklist");
    if (!port_map) {
        fprintf(stderr, "Failed to find port_blacklist map\n");
        bpf_object__close(obj);
        return 1;
    }
    __u32 black_ip = ntohl(inet_addr(BLACK_IP));
    __u16 black_port = htons(BLACK_PORT);
    __u8 value = 1;
    if (bpf_map_update_elem(bpf_map__fd(ip_map), &black_ip, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update ip_blacklist map\n");
        bpf_object__close(obj);
        return 1;
    }
    if (bpf_map_update_elem(bpf_map__fd(port_map), &black_port, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update port_blacklist map\n");
        bpf_object__close(obj);
        return 1;
    }
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return 1;
    }
    
    prog_fd = bpf_program__fd(prog);
    
    UNITY_BEGIN();
    printf("=== Firewall XDP Filter Unit Tests ===\n\n");

    RUN_TEST(test_expect_drop);
    RUN_TEST(test_expect_pass);

    bpf_object__close(obj);
    return UNITY_END();
}