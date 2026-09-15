#pragma once
#include <stdlib.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lib/cJSON.h"

int extract_valid_ip(cJSON* ip, __u32* out_ips);
int extract_valid_port(cJSON* port, __u16* out_ports);
int ip_list_2_map(cJSON* ip_list, struct bpf_map *black_map);
int port_list_2_map(cJSON* port_list, struct bpf_map *black_map);
