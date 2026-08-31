#pragma once
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lib/cJSON.h"

int extract_valid_ip(cJSON* ip, uint32_t* out_ips);
int ip_list_2_map(cJSON* ip_list, struct bpf_map *black_map);
int port_list_2_map(cJSON* port_list, struct bpf_map *black_map);