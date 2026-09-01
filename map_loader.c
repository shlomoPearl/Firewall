#include "map_loader.h"

int extract_valid_ip(cJSON* ip, uint32_t* out_ips){
    if (cJSON_IsString(ip)) {
        const char* ip_str = ip->valuestring;
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", ip_str);
            return -1;
        }
        *out_ips = ntohl(addr.s_addr); // host order as bpf 
        return 0;
    }
    return -1;
}

int extract_valid_port(cJSON* port, uint16_t* out_port){
    if (cJSON_IsString(port)) {
        const char* port_str = port->valuestring;
        int port_num = atoi(port_str);
        if (port_num < 1 || port_num > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", port_str);
            return -1;
        }
        *out_port = (uint16_t)port_num;
        return 0;
    }
    return -1;
}

int ip_list_2_map(cJSON* ip_list, struct bpf_map *black_map) {
    cJSON* ip = NULL;
    cJSON_ArrayForEach(ip, ip_list) {
        uint32_t *ip_key = NULL;
        if (extract_valid_ip(ip, ip_key) != 0){
            fprintf(stderr, "Failed to extract IP: %s\n", ip->valuestring);
            return -1;    
        }
        uint8_t value = 1; // Value to indicate blocked
        if (bpf_map_update_elem(bpf_map__fd(black_map), &ip_key, &value, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update black_map for IP: %s\n", ip->valuestring);
            return -1;
        }
    }
    return 0;
}
int port_list_2_map(cJSON* port_list, struct bpf_map *black_map) {
    cJSON* port = NULL;
    cJSON_ArrayForEach(port, port_list) {
        uint16_t* port_key= NULL;
        if (extract_valid_port(port, port_key) != 0){
            fprintf(stderr, "Failed to extract PORT: %s\n", port->valuestring);
            return -1;
        }
        uint8_t value = 1; 
        if (bpf_map_update_elem(bpf_map__fd(black_map), &port_key, &value, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update black_map for port: %s\n", port->valuestring);
            return -1;
        }
    }
    return 0;
}
