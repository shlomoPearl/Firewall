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
    struct pollfd pfd = {
        .fd = inotify_fd,
        .events = POLLIN
    };
    int poll_result = poll(&pfd, 1, 500); // 0.5 second timeout
    if (poll_result == 0) {
        return 0;  // Timeout: no event; check stop_requested again
    }
    if (poll_result < 0) {
        if (errno == EINTR) {
            return 0;  // Interrupted by a signal
        }

        perror("poll");
        return -1;
    }
    if (pfd.revents & (POLLERR | POLLNVAL)) {
        fprintf(stderr, "Error on inotify file descriptor\n");
        return -1;
    }

    if (!(pfd.revents & POLLIN)) {
        return 0;
    }
    ssize_t length = read(inotify_fd, buffer, sizeof(buffer));
     if (length < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            return 0;
        }

        perror("read inotify");
        return -1;
    }

    ssize_t i = 0;
    while (i < length) {
        struct inotify_event* event = (struct inotify_event*)(buffer + i);
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
