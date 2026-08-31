#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "config.h"
#include "lib/cJSON.h"
#include "rules_parser.h"
#include "rules_notify.h"
#include "map_loader.h"
#include "firewall.skel.h"  // Generated skeleton header

void handle_signal(int sig);
int main(int argc, char **argv);