#include <sys/inotify.h>
#include <unistd.h>
#include "config.h"

int setup_inotify() {
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd < 0) {
        perror("inotify_init");
        return -1;
    }

    int watch_descriptor = inotify_add_watch(inotify_fd, RULES_FILE, IN_CLOSE_WRITE);
    if (watch_descriptor < 0) {
        perror("inotify_add_watch");
        close(inotify_fd);
        return -1;
    }
    return inotify_fd;
}

int watch_rules_changes(int inotify_fd) {
    char buffer[RULES_FILE_SIZE]; 
    int length = read(inotify_fd, buffer, sizeof(buffer));
    
}