#include "firewall.h"

int running = 1;
int err;
cJSON* rules_json;
struct firewall_bpf *skel;

void handle_signal(int sig) {
    printf("Received signal %d, exiting...\n", sig);
    cJSON_Delete(rules_json);
    bpf_link__destroy(skel->links.xdp_filter);
    firewall_bpf__destroy(skel);
    exit(1);
    // return err;
    // goto cleanup;
    // running = 0;
}

void stop(){
    printf("EXIT...\n", sig);
    bpf_link__destroy(skel->links.xdp_filter);
    firewall_bpf__destroy(skel);
    exit(1);
}


int main(int argc, char **argv) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    struct bpf_map *ip_map = NULL;
    struct bpf_map *port_map = NULL;
    int ifindex;

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

    /* Load & verify BPF programs */
    err = firewall_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        stop();
    }

    /* Attach XDP program */
    err = firewall_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        stop();
    }

    /* Attach the XDP program to the specified interface */
    skel->links.xdp_filter = bpf_program__attach_xdp(skel->progs.xdp_filter, ifindex);
    if (!skel->links.xdp_filter)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        stop();
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    // initialize the black_map
    ip_map = bpf_object__find_map_by_name(skel->obj, "ip_blacklist");
    port_map = bpf_object__find_map_by_name(skel->obj, "port_blacklist");
    if (!ip_map || !port_map)
    {
        fprintf(stderr, "Failed to find ip/port_map\n");
        err = -1;
        stop();
    }

    // first load the rules from the file
    rules_json = setup_json(rules_file);
    if (rules_json == NULL) {
        fprintf(stderr, "Failed to set up JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        stop();
    }
    if (ip_list_2_map(get_blacklist(rules_json, IP_LST_N), ip_map) != 0) {
        fprintf(stderr, "Failed to populate ip_map from JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        stop();
    }
    if (port_list_2_map(get_blacklist(rules_json, PORT_LST_N), port_map) != 0) {
        fprintf(stderr, "Failed to populate port_map from JSON rules\n");
        err = -1;
        cJSON_Delete(rules_json);
        stop();
    }

    int inotify_fd = setup_inotify(rules_file);
    if (inotify_fd < 0) {
        fprintf(stderr, "Failed to set up inotify\n");
        err = -1;
        cJSON_Delete(rules_json);
        stop();
    }

    while (running) {
        int reload_needed = watch_rules_changes(inotify_fd);
        if (reload_needed) {
            printf("Reloading rules...\n");
            rules_json = setup_json(rules_file);
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
}