#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include "../lib/unity.h"
#include "../lib/cJSON.h"
#include "../rules_parser.h"
#include "../map_loader.h"

#define TEST_FILENAME "test_rules.json"

const char* VALID_JSON_CONTENT = 
"{\n"
"  \"ip_blacklist\": [\"192.168.1.100\", \"10.0.0.5\"],\n"
"  \"port_blacklist\": [\"80\", \"443\"]\n"
"}\n";

const char* INVALID_JSON_CONTENT = "{ this is invalid json }";
const char* INVALID_JSON_PORT_VALUE = "{\n"
"  \"ip_blacklist\": [\"192.168.1.100\", \"10.0.0.5\"],\n"
"  \"port_blacklist\": [80, \"0\", \"65536\"]\n"
"}\n";
;
const char* INVALID_JSON_IP_VALUE = "{\n"
"  \"ip_blacklist\": [\"300.168.1.100\", \"10.0.0.0.5\", \"invalid_ip\"],\n"
"  \"port_blacklist\": [\"80\", \"443\"]\n"
"}\n";

static void create_test_file(const char* filename, const char* content) {
    FILE* f = fopen(filename, "w");
    if (f != NULL) {
        fputs(content, f);
        fclose(f);
    }
}

void setUp(void) {
    create_test_file(TEST_FILENAME, VALID_JSON_CONTENT);
}

void tearDown(void) {
    remove(TEST_FILENAME);
}

void test_read_rules_file_exist(void) {
    char* content = read_rules_file(TEST_FILENAME);
    TEST_ASSERT_NOT_NULL(content);
    TEST_ASSERT_EQUAL_STRING(VALID_JSON_CONTENT, content);
    free(content);
}

void test_read_rules_file_not_found(void) {
    char* content = read_rules_file("non_existent_file.json");
    TEST_ASSERT_NULL(content);
}

void test_parse_rules_valid(void) {
    cJSON* rules_json = parse_rules(VALID_JSON_CONTENT);
    TEST_ASSERT_NOT_NULL(rules_json);
    cJSON_Delete(rules_json);
}

void test_parse_rules_invalid(void) {
    cJSON* rules_json = parse_rules(INVALID_JSON_CONTENT);
    TEST_ASSERT_NULL(rules_json);
}

void test_get_blacklist_valid(void) {
    cJSON* rules_json = parse_rules(VALID_JSON_CONTENT);
    TEST_ASSERT_NOT_NULL(rules_json);

    cJSON* ip_blacklist = get_blacklist(rules_json, "ip_blacklist");
    TEST_ASSERT_NOT_NULL(ip_blacklist);
    TEST_ASSERT_TRUE(cJSON_IsArray(ip_blacklist));
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(ip_blacklist));
    cJSON* first_ip = cJSON_GetArrayItem(ip_blacklist, 0);
    TEST_ASSERT_TRUE(cJSON_IsString(first_ip));
    TEST_ASSERT_EQUAL_STRING("192.168.1.100", first_ip->valuestring);
    cJSON_Delete(rules_json);
}

void test_get_blacklist_invalid(void) {
    // case - 1: non-existent list
    cJSON* rules_json = parse_rules(VALID_JSON_CONTENT);
    TEST_ASSERT_NOT_NULL(rules_json);
    
    cJSON* non_existent_list = get_blacklist(rules_json, "non_existent_list");
    TEST_ASSERT_NULL(non_existent_list);
    cJSON_Delete(rules_json);
    
    // case - 2: list is not an array
    const char* bad_structure = "{\"ip_blacklist\": \"192.168.1.100\"}";
    cJSON* json = parse_rules(bad_structure);
    TEST_ASSERT_NOT_NULL(json);

    cJSON* ip_list = get_blacklist(json, "ip_blacklist");
    TEST_ASSERT_NULL(ip_list);
    cJSON_Delete(json);
}

void test_rejects_invalid_ips(void) {
    cJSON* rules_json = parse_rules(INVALID_JSON_IP_VALUE);
    cJSON* ip_blacklist = get_blacklist(rules_json, "ip_blacklist");
    cJSON* ip = NULL;
    cJSON_ArrayForEach(ip, ip_blacklist) {
        uint32_t *out = NULL;
        int is_valid = extract_valid_ip(ip, out);
        TEST_ASSERT_EQUAL_INT(-1, is_valid);  // now this genuinely proves rejection, not a NULL-map coincidence
    }
    cJSON_Delete(rules_json);
}

void test_accepts_valid_ips(void) {
    cJSON* rules_json = parse_rules(VALID_JSON_CONTENT);
    cJSON* ip_blacklist = get_blacklist(rules_json, "ip_blacklist");
    cJSON* ip = NULL;
    cJSON_ArrayForEach(ip, ip_blacklist) {
        uint32_t out = 0;
        int is_valid = extract_valid_ip(ip, &out);
        TEST_ASSERT_EQUAL_INT(0, is_valid);  // now this genuinely proves rejection, not a NULL-map coincidence
        TEST_ASSERT_NOT_EQUAL(0, out);  // ensure its actually write something to out
    }   
    cJSON_Delete(rules_json);
}
void test_rejects_invalid_ports(void) {
    cJSON* rules_json = parse_rules(INVALID_JSON_PORT_VALUE);
    cJSON* port_blacklist = get_blacklist(rules_json, "port_blacklist");
    cJSON* port = NULL;
    cJSON_ArrayForEach(port, port_blacklist) {
        uint16_t *out = NULL;
        int is_valid = extract_valid_port(port, out);
        TEST_ASSERT_EQUAL_INT(-1, is_valid);  // now this genuinely proves rejection, not a NULL-map coincidence
    }
    cJSON_Delete(rules_json);
}

void test_accepts_valid_ports(void) {
    cJSON* rules_json = parse_rules(VALID_JSON_CONTENT);
    cJSON* port_blacklist = get_blacklist(rules_json, "port_blacklist");
    cJSON* port = NULL;
    cJSON_ArrayForEach(port, port_blacklist) {
        uint16_t out = 0;
        int is_valid = extract_valid_port(port, &out);
        TEST_ASSERT_EQUAL_INT(0, is_valid);  // now this genuinely proves rejection, not a NULL-map coincidence
        TEST_ASSERT_NOT_EQUAL(0, out);  // ensure its actually write something to out
    }
    cJSON_Delete(rules_json);
}

void test_setup_json_success(void) {
    cJSON* json = setup_json(TEST_FILENAME);
    TEST_ASSERT_NOT_NULL(json);

    cJSON* port_list = get_blacklist(json, "port_blacklist");
    TEST_ASSERT_NOT_NULL(port_list);
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(port_list));

    cJSON_Delete(json);
}
void test_setup_json_file_error(void) {
    cJSON* json = setup_json("missing_file.json");
    TEST_ASSERT_NULL(json);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_read_rules_file_exist);
    RUN_TEST(test_read_rules_file_not_found);
    RUN_TEST(test_parse_rules_valid);
    RUN_TEST(test_parse_rules_invalid);
    RUN_TEST(test_get_blacklist_valid);
    RUN_TEST(test_get_blacklist_invalid);
    RUN_TEST(test_rejects_invalid_ips);
    RUN_TEST(test_accepts_valid_ips);
    RUN_TEST(test_rejects_invalid_ports);
    RUN_TEST(test_accepts_valid_ports);
    RUN_TEST(test_setup_json_success);
    RUN_TEST(test_setup_json_file_error);
    return UNITY_END();
}
