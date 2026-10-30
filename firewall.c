#include "firewall.h"

cJSON* rules_json;
struct firewall_bpf *skel;

static volatile sig_atomic_t stop_requested = 0;

void handle_signal(int sig) {
    printf("Received signal %d, exiting...\n", sig);
    stop_requested = 1;
}

static void stop(int inotify_fd) {
    if (inotify_fd >= 0) {
        close(inotify_fd);
    }
    if (skel) {
        firewall_bpf__destroy(skel);
        skel = NULL;
    }

    if (rules_json) {
        cJSON_Delete(rules_json);
        rules_json = NULL;
    }
}


int main(int argc, char **argv) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    struct bpf_map *ip_map = NULL;
    struct bpf_map *port_map = NULL;
    int ifindex;
    int inotify_fd = -1;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ifname>\n <prod/test>", argv[0]);
        return 1;
    }
    
    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0){
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    const char *rules_file_mod = argv[2];
    if (strcmp(rules_file_mod, "test") && strcmp(rules_file_mod, "prod")){
        fprintf(stderr, "Usage: %s <ifname>\n <prod/test> got %s", argv[0], argv[2]);
        return 1;
    }
    char * rules_file;
    if (!strcmp(rules_file_mod, "test")){
        rules_file = TEST_RULES_FILE;
    } else {
        rules_file = RULES_FILE;
    }

    /* Open and load BPF application */
    skel = firewall_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs 
    if (firewall_bpf__load(skel)) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        stop(inotify_fd);
        return 1;
    }

    // Attach the XDP program to the specified interface 
    skel->links.xdp_filter = bpf_program__attach_xdp(skel->progs.xdp_filter, ifindex);
    if (!skel->links.xdp_filter || libbpf_get_error(skel->links.xdp_filter)) {
        fprintf(stderr, "Failed to attach XDP program");
        skel->links.xdp_filter = NULL;
        stop(inotify_fd);
        return 1;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    // initialize the black_map
    ip_map = bpf_object__find_map_by_name(skel->obj, "ip_blacklist");
    port_map = bpf_object__find_map_by_name(skel->obj, "port_blacklist");
    if (!ip_map || !port_map)
    {
        fprintf(stderr, "Failed to find ip/port_map\n");
        stop(inotify_fd);
        return 1;
    }

    // first load the rules from the file
    rules_json = setup_json(rules_file);
    if (rules_json == NULL) {
        fprintf(stderr, "Failed to set up JSON rules\n");
        stop(inotify_fd);
        return 1;
    }
    clear_map(ip_map);
    if (ip_list_2_map(get_blacklist(rules_json, IP_LST_N), ip_map) != 0) {
        fprintf(stderr, "Failed to populate ip_map from JSON rules\n");
        stop(inotify_fd);
        return 1;
    }
    clear_map(port_map);
    if (port_list_2_map(get_blacklist(rules_json, PORT_LST_N), port_map) != 0) {
        fprintf(stderr, "Failed to populate port_map from JSON rules\n");
        stop(inotify_fd);
        return 1;
    }

    inotify_fd = setup_inotify(rules_file);
    if (inotify_fd < 0) {
        fprintf(stderr, "Failed to set up inotify\n");
        stop(inotify_fd);
        return 1;
    }

    while (!stop_requested) {
        int reload_needed = watch_rules_changes(inotify_fd);
        if (reload_needed < 0) {
            fprintf(stderr, "Error while watching rules changes\n");
            break;
        }
        if (reload_needed == 1) {
            continue; 
        }

        cJSON *new_rules = setup_json(rules_file);
        if (new_rules == NULL) {
            fprintf(stderr, "Failed to set up JSON rules\n");
            continue; 
        }
        clear_map(ip_map);
        if (ip_list_2_map(get_blacklist(new_rules, IP_LST_N), ip_map) != 0) {
            fprintf(stderr, "Failed to populate ip_map\n");
   	    cJSON_Delete(new_rules);
            continue;
        }
        clear_map(port_map);
        if (port_list_2_map(get_blacklist(new_rules, PORT_LST_N), port_map) != 0) {
            fprintf(stderr, "Failed to populate port_map\n");
	    cJSON_Delete(new_rules);
            continue;
        }
        cJSON_Delete(rules_json);
	rules_json = new_rules;
    }
    stop(inotify_fd);
    return 0;
}
