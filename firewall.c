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
#include "cJSON.h"
#include "rules_parser.h"
#include "rules_notify.h"
#include "firewall.skel.h"  // Generated skeleton header

// Callback function to handle events from the BPF program (currently does nothing)
static int handle_event(void *ctx, void *data, size_t data_sz){    
    return 0;
}

int ip_list_2_map(cJSON* ip_list, struct bpf_map *black_map) {
    cJSON* ip = NULL;
    cJSON_ArrayForEach(ip, ip_list) {
        if (cJSON_IsString(ip)) {
            const char* ip_str = ip->valuestring;
            struct in_addr addr;
            if (inet_pton(AF_INET, ip_str, &addr) != 1) {
                fprintf(stderr, "Invalid IP address: %s\n", ip_str);
                continue;
            }
            uint32_t ip_key = addr.s_addr; // Network byte order
            uint32_t value = 1; // Value to indicate blocked
            if (bpf_map_update_elem(bpf_map__fd(black_map), &ip_key, &value, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to update black_map for IP: %s\n", ip_str);
            }
        }
    }
    return 0;
}
int port_list_2_map(cJSON* port_list, struct bpf_map *black_map) {
    cJSON* port = NULL;
    cJSON_ArrayForEach(port, port_list) {
        if (cJSON_IsString(port)) {
            const char* port_str = port->valuestring;
            uint16_t port_num = (uint16_t)atoi(port_str);
            if (port_num == 0) {
                fprintf(stderr, "Invalid port number: %s\n", port_str);
                continue;
            }
            uint32_t port_key = (uint32_t)port_num; // Store as uint32_t for the map
            uint32_t value = 1; // Value to indicate blocked
            if (bpf_map_update_elem(bpf_map__fd(black_map), &port_key, &value, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to update black_map for port: %s\n", port_str);
            }
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    struct firewall_bpf *skel;
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
    skel = firewall_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = firewall_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach XDP program */
    err = firewall_bpf__attach(skel);
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

    // initialize the black_map
    black_map = bpf_object__find_map_by_name(skel->obj, "black_map");
    if (!black_map)
    {
        fprintf(stderr, "Failed to find black_map\n");
        err = -1;
        goto cleanup;
    }

    // first load the rules from the file
    cJSON* rules_json = setup_json(RULES_FILE);
    if (rules_json == NULL) {
        fprintf(stderr, "Failed to set up JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        goto cleanup;
    }
    if (ip_list_2_map(get_blacklist(rules_json, IP_LST_N), black_map) != 0) {
        fprintf(stderr, "Failed to populate black_map from JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        goto cleanup;
    }
    if (port_list_2_map(get_blacklist(rules_json, PORT_LST_N), black_map) != 0) {
        fprintf(stderr, "Failed to populate black_map from JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        goto cleanup;
    }

    int inotify_fd = setup_inotify();
    if (inotify_fd < 0) {
        fprintf(stderr, "Failed to set up inotify\n");
        err = -1;
        cJSON_Delete(rules_json);
        goto cleanup;
    }

    while (1) {
        int reload_needed = watch_rules_changes(inotify_fd);
        if (reload_needed) {
            printf("Reloading rules...\n");
            rules_json = setup_json(RULES_FILE);
            if (rules_json == NULL) {
                fprintf(stderr, "Failed to set up JSON rules\n");
                continue; 
            }
            if (ip_list_2_map(get_blacklist(rules_json, IP_LST_N), black_map) != 0) {
                fprintf(stderr, "Failed to populate black_map from JSON rules\n");
                continue;
            }
            if (port_list_2_map(get_blacklist(rules_json, PORT_LST_N), black_map) != 0) {
                fprintf(stderr, "Failed to populate black_map from JSON rules\n");
                continue;
            }   
        }
    }

cleanup:
    bpf_link__destroy(skel->links.xdp_pass);
    firewall_bpf__destroy(skel);
    return -err;
}
