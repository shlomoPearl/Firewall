#pragma once
#include <sys/inotify.h>
#include <unistd.h>
#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include "config.h"

int setup_inotify(const char*);
int watch_rules_changes(int inotify_fd);
