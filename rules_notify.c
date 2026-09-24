#include "rules_notify.h"

static char g_watched_name[256];
int setup_inotify(const char* rules_file) {
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return -1;
    }

    char dir_buf[512], base_buf[512];
    strncpy(dir_buf, rules_file, sizeof(dir_buf) - 1);
    strncpy(base_buf, rules_file, sizeof(base_buf) - 1);
    char *dir = dirname(dir_buf);
    char *base = basename(base_buf);
    strncpy(g_watched_name, base, sizeof(g_watched_name) - 1);
    printf("dir - %s\n", dir);
    printf("base - %s\n", base);
    printf("g - %s\n", g_watched_name);
    int watch_descriptor = inotify_add_watch(inotify_fd, dir, IN_CLOSE_WRITE | IN_MOVED_TO);
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
        if (event->len > 0 && strcmp(event->name, g_watched_name) == 0){
	    if (event->mask & IN_CLOSE_WRITE) {
                printf("Rules file changed - IN_CLOSE_WRITE, reloading...\n");
                return 1; 
            }
            if (event->mask & IN_MOVED_TO) {
                printf("Rules file moved to - IN_MOVED_TO, reloading...\n");
                return 1; 
            }
	}
        i += sizeof(struct inotify_event) + event->len;
    }
    return 0; 
}
