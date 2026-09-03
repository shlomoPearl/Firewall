#include "firewall.h"

int running = 1;

void handle_signal(int sig) {
    printf("Received signal %d, exiting...\n", sig);
    running = 0;
}


int main(int argc, char **argv) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    struct firewall_bpf *skel;
    struct bpf_map *ip_map = NULL;
    struct bpf_map *port_map = NULL;
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
    skel->links.xdp_filter = bpf_program__attach_xdp(skel->progs.xdp_filter, ifindex);
    if (!skel->links.xdp_filter)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    // initialize the black_map
    ip_map = bpf_object__find_map_by_name(skel->obj, "ip_blacklist");
    port_map = bpf_object__find_map_by_name(skel->obj, "port_blacklist");
    if (!ip_map || !port_map)
    {
        fprintf(stderr, "Failed to find ip/port_map\n");
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
    if (ip_list_2_map(get_blacklist(rules_json, IP_LST_N), ip_map) != 0) {
        fprintf(stderr, "Failed to populate ip_map from JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        goto cleanup;
    }
    if (port_list_2_map(get_blacklist(rules_json, PORT_LST_N), port_map) != 0) {
        fprintf(stderr, "Failed to populate port_map from JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        goto cleanup;
    }

    int inotify_fd = setup_inotify(RULES_FILE);
    if (inotify_fd < 0) {
        fprintf(stderr, "Failed to set up inotify\n");
        err = -1;
        cJSON_Delete(rules_json);
        goto cleanup;
    }

    while (running) {
        int reload_needed = watch_rules_changes(inotify_fd);
        if (reload_needed) {
            printf("Reloading rules...\n");
            rules_json = setup_json(RULES_FILE);
            if (rules_json == NULL) {
                fprintf(stderr, "Failed to set up JSON rules\n");
                continue; 
            }
            if (ip_list_2_map(get_blacklist(rules_json, IP_LST_N), ip_map) != 0) {
                fprintf(stderr, "Failed to populate ip_map from JSON rules\n");
                continue;
            }
            if (port_list_2_map(get_blacklist(rules_json, PORT_LST_N), port_map) != 0) {
                fprintf(stderr, "Failed to populate port_map from JSON rules\n");
                continue;
            }
            cJSON_Delete(rules_json);
        }
    }

    cleanup:
        bpf_link__destroy(skel->links.xdp_filter);
        firewall_bpf__destroy(skel);
        return -err;
}
