#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "config.h"

char* read_rules_file(const char* filename);
cJSON* parse_rules(const char* rules_content);
cJSON* get_blacklist(cJSON* rules_json, const char* list_name); 
cJSON* setup_json(const char* rules_file);