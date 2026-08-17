#pragma once
#include <sys/inotify.h>
#include <unistd.h>
#include <stdio.h>
#include "config.h"

int setup_inotify();
int watch_rules_changes(int inotify_fd);
