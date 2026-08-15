#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp-wall.skel.h"  // Generated skeleton header

#define MAX_TCP_HEADER_BYTES 60  // Maximum TCP header size in bytes

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

    

cleanup:
    bpf_map__free(black_map);
    xdp_wall_bpf__destroy(skel);
    return -err;
}
