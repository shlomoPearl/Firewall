#include "rules_parser.h"

char* read_rules_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open rules file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    if (length < 0) {
        perror("Failed to determine rules file length");
        fclose(file);
        return NULL;
    }
    fseek(file, 0, SEEK_SET);

    char* content = malloc(length + 1);
    if (content == NULL) {
        perror("Failed to allocate memory for rules file content");
        fclose(file);
        return NULL;
    }

    int bytes_read = fread(content, 1, length, file);
    if (bytes_read != length) {
        perror("Failed to read rules file content");
        free(content);
        fclose(file);
        return NULL;
    }
    content[length] = '\0';
    fclose(file);

    return content;
}

cJSON* parse_rules(const char* rules_content) {
    cJSON* rules_json = cJSON_Parse(rules_content);
    if (rules_json == NULL) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return NULL;
    }
    return rules_json;
}

cJSON* get_blacklist(cJSON* rules_json, const char* list_name) {
    cJSON* blacklist = cJSON_GetObjectItemCaseSensitive(rules_json, list_name);
    if (!cJSON_IsArray(blacklist)) {
        fprintf(stderr, "%s is not an array\n", list_name);
        return NULL;
    }
    return blacklist;
}

cJSON* setup_json(const char* rules_file) {
    char* rules_content = read_rules_file(rules_file);
    if (rules_content == NULL) {
        return NULL;
    }

    cJSON* rules_json = parse_rules(rules_content);
    free(rules_content);  // Free the content after parsing
    if (rules_json == NULL) {
        return NULL;
    }
    return rules_json;
}


// main for testing purposes
// int main() {
//     char* rules_content = read_rules_file(RULES_FILE);
//     if (rules_content == NULL) {
//         return EXIT_FAILURE;
//     }
//     cJSON* rules_json = parse_rules(rules_content);
//     if (rules_json == NULL) {
//         free(rules_content);
//         return EXIT_FAILURE;
//     }   
//     cJSON* ip_blacklist = get_blacklist(rules_json, IP_LST_N);
//     cJSON* port_blacklist = get_blacklist(rules_json, PORT_LST_N);
//     // Print the blacklists for testing
//     if (ip_blacklist != NULL) {
//         printf("IP Blacklist:\n");
        // cJSON* ip = NULL;
        // cJSON_ArrayForEach(ip, ip_blacklist) {
        //     if (cJSON_IsString(ip)) {
        //         printf("%s\n", ip->valuestring);
        //     }
        // }
//     }
//     if (port_blacklist != NULL) {   
//         printf("Port Blacklist:\n");
        // cJSON* port = NULL;
        // cJSON_ArrayForEach(port, port_blacklist) {
        //     if (cJSON_IsString(port)) {
        //         printf("%s\n", port->valuestring);
        //     }
        // }
//     }
//     cJSON_Delete(rules_json);
//     free(rules_content);
//     return 0;
// }
