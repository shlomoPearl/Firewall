#include "rules_notify.h"

int setup_inotify(const char* rules_file) {
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return -1;
    }

    int watch_descriptor = inotify_add_watch(inotify_fd, rules_file, IN_CLOSE_WRITE | IN_MOVED_TO);
    if (watch_descriptor < 0) {
        perror("inotify_add_watch");
        close(inotify_fd);
        return -1;
    }
    return inotify_fd;
}

int watch_rules_changes(int inotify_fd) {
    char buffer[BUFFER_NOTIFY_SIZE]; 
    int length = read(inotify_fd, buffer, sizeof(buffer));
    struct inotify_event* event;
    int i = 0;
    while (i < length) {
        event = (struct inotify_event*)&buffer[i];
        if (event->mask & IN_CLOSE_WRITE) {
            printf("Rules file changed - IN_CLOSE_WRITE, reloading...\n");
            return 1; 
        }
        if (event->mask & IN_MOVED_TO) {
            printf("Rules file moved to - IN_MOVED_TO, reloading...\n");
            return 1; 
        }
        i += sizeof(struct inotify_event) + event->len;
    }
    return 0; 
}
