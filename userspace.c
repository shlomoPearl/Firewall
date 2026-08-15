#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "config.h"
#include "rules_parser.c"
#include "rules_notify.c"
#include "xdp-wall.skel.h"  // Generated skeleton header

// Callback function to handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz){

    return 0;
}

int main(int argc, char **argv)
{
    struct xdp_wall_bpf *skel;
    struct bpf_map *black_map = NULL;
    int ifindex;
    int err;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    /* Open and load BPF application */
    skel = xdp_wall_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = xdp_wall_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach XDP program */
    err = xdp_wall_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach the XDP program to the specified interface */
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    /* Set up ring buffer polling */
    black_map = bpf_map__new(bpf_map__fd(skel->maps.black_map), handle_event, NULL, NULL);
    if (!black_map)
    {
        fprintf(stderr, "Failed to create map\n");
        err = -1;
        goto cleanup;
    }

    // first load the rules from the file
    cJSON* rules_json = setup_json(RULES_FILE);
    if (rules_json == NULL) {
        fprintf(stderr, "Failed to set up JSON rules\n");
        err = -1;
        goto cleanup;
    }
    cJSON* ip_blacklist = get_blacklist(rules_json, IP_LST_N);
    cJSON* port_blacklist = get_blacklist(rules_json, PORT_LST_N);
    if (ip_blacklist == NULL || port_blacklist == NULL) {
        fprintf(stderr, "Failed to get blacklists\n");
        err = -1;
        goto cleanup;
    }
    cJSON* ip = NULL;
    cJSON_ArrayForEach(ip, ip_blacklist) {
        if (cJSON_IsString(ip)) {
            const char* ip_str = ip->valuestring;
            struct in_addr addr;
            if (inet_pton(AF_INET, ip_str, &addr) != 1) {
                fprintf(stderr, "Invalid IP address: %s\n", ip_str);
                continue;
            }
            uint32_t ip_key = addr.s_addr; // Network byte order
            uint32_t value = 1; // Value to indicate blocked
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.black_map), &ip_key, &value, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to update black_map for IP: %s\n", ip_str);
            }
        }
    }
    cJSON* port = NULL;
    cJSON_ArrayForEach(port, port_blacklist) {
        if (cJSON_IsString(port)) {
            const char* port_str = port->valuestring;
            uint16_t port_num = (uint16_t)atoi(port_str);
            if (port_num == 0) {
                fprintf(stderr, "Invalid port number: %s\n", port_str);
                continue;
            }
            uint32_t port_key = (uint32_t)port_num; // Store as uint32_t for the map
            uint32_t value = 1; // Value to indicate blocked
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.black_map), &port_key, &value, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to update black_map for port: %s\n", port_str);
            }
        }
        
    while(1){
                
    }

cleanup:
    bpf_map__free(black_map);
    xdp_wall_bpf__destroy(skel);
    return -err;
}
