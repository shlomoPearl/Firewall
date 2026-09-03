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


#define PACKET_SIZE 64
#define BLACK_IP "192.192.192.192"
#define BLACK_PORT 65000
#define ALLOWED_IP "192.168.1.1"
#define ALLOWED_PORT 65001
#define DST_IP "127.0.0.1"
#define SRC_PORT 80


struct test_result {
    const char *test_name;
    int expected_action;
    int actual_action;
    bool passed;
};

static void create_ipv4_packet(char *packet, __u8 protocol, const char *src_ip, const char *dst_ip, __u16 src_port, __u16 dst_port) {
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

static struct test_result run_test_case(int prog_fd, const char *test_name, int expected_action, const char *packet) {
    struct test_result result = {
        .test_name = test_name,
        .expected_action = expected_action,
        .passed = false
    };
    
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = packet,
        .data_size_in = PACKET_SIZE,
        .repeat = 1,
    );    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        fprintf(stderr, "Failed to run test %s: %s\n",
                test_name, strerror(errno));
        return result;
    }

    result.actual_action = opts.retval;
    result.passed = (result.actual_action == result.expected_action);

    return result;
}                

void setUp(void) {
    // This function is called before each test case

}

void tearDown(void) {
    // This function is called after each test case
}

void test_xdp_drop_black_ip(int prog_fd, const char* packet) {
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = packet,
        .data_size_in = PACKET_SIZE,
        .repeat = 1,
    );    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    TEST_ASSERT_EQUAL_INT(0, err);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, opts.retval);
}

void test_xdp_drop_black_port(int prog_fd, const char* packet) {
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = packet,
        .data_size_in = PACKET_SIZE,
        .repeat = 1,
    );    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    TEST_ASSERT_EQUAL_INT(0, err);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, opts.retval);
}

void test_xdp_drop_malformed(int prog_fd, const char* packet) {
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = packet,
        .data_size_in = PACKET_SIZE,
        .repeat = 1,
    );    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    TEST_ASSERT_EQUAL_INT(0, err);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, opts.retval);
}

void test_xdp_drop_fragments(int prog_fd, const char* packet) {
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = packet,
        .data_size_in = PACKET_SIZE,
        .repeat = 1,
    );    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    TEST_ASSERT_EQUAL_INT(0, err);
    TEST_ASSERT_EQUAL_INT(XDP_DROP, opts.retval);
}

void test_xdp_pass(int prog_fd, const char* packet) {
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = packet,
        .data_size_in = PACKET_SIZE,
        .repeat = 1,
    );    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    TEST_ASSERT_EQUAL_INT(0, err);
    TEST_ASSERT_EQUAL_INT(XDP_PASS, opts.retval);
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
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return 1;
    }
    
    int prog_fd = bpf_program__fd(prog);
    
    UNITY_BEGIN();
    printf("=== Firewall XDP Filter Unit Tests ===\n\n");

    // Define test cases
    struct {
        const char *name;
        __u8 protocol;
        const char *src_ip;
        const char *dst_ip;
        int src_port;
        int dst_port;
        int expected_action;
    } test_cases[] = {
        {"black ip (TCP) - packet should be dropped", IPPROTO_TCP,BLACK_IP, DST_IP, SRC_PORT, ALLOWED_PORT, XDP_DROP},
        {"black port (TCP) - packet should be dropped", IPPROTO_TCP, ALLOWED_IP, DST_IP, SRC_PORT, BLACK_PORT, XDP_DROP},
        {"black ip (UDP) - packet should be dropped", IPPROTO_UDP, BLACK_IP, DST_IP, SRC_PORT, ALLOWED_PORT, XDP_DROP},
        {"black port (UDP) - packet should be dropped", IPPROTO_UDP, ALLOWED_IP, DST_IP, SRC_PORT, BLACK_PORT, XDP_DROP},
        {"packet (TCP) - should pass", IPPROTO_TCP, ALLOWED_IP, DST_IP, SRC_PORT, ALLOWED_PORT, XDP_PASS},
        {"packet (UDP) - should pass", IPPROTO_UDP, ALLOWED_IP, DST_IP, SRC_PORT, ALLOWED_PORT, XDP_PASS},
    };

    int passed_tests = 0;
    int total_tests = sizeof(test_cases) / sizeof(test_cases[0]);

    // Run all test cases
    for (int i = 0; i < total_tests; i++) {
        char packet[PACKET_SIZE];
        create_ipv4_packet(packet, test_cases[i].protocol, test_cases[i].src_ip, test_cases[i].dst_ip,
                                                           test_cases[i].src_port, test_cases[i].dst_port);
        struct test_result result = run_test_case(
            prog_fd,
            test_cases[i].name,
            test_cases[i].expected_action,
            packet
        );

        printf("Test: %s\n", result.test_name);
        printf("  Expected: %s (%d)\n",
               result.expected_action == XDP_DROP ? "XDP_DROP" : "XDP_PASS",
               result.expected_action);
        printf("  Actual:   %s (%d)\n",
               result.actual_action == XDP_DROP ? "XDP_DROP" : "XDP_PASS",
               result.actual_action);
        printf("  Result:   %s\n\n", result.passed ? "PASS" : "FAIL");

        if (result.passed) {
            passed_tests++;
        }
    }

    printf("=== Test Summary ===\n");
    printf("Passed: %d/%d tests\n", passed_tests, total_tests);
    printf("Success rate: %.2f%%\n\n",
           (double)passed_tests / total_tests * 100);

    bpf_object__close(obj);
    return UNITY_END();
    // return (passed_tests == total_tests) ? 0 : 1;
}