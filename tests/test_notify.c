#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include "../lib/unity.h"
#include "../lib/cJSON.h"
#include "../rules_notify.h"

#define NOTIFY_TEST_FILE "test_rules.json"

static void create_test_file(const char* filename) {
    FILE* f = fopen(filename, "w");
    if (f != NULL) {
        fputs("{\"test\": \"data\"}", f);
        fclose(f);
    }
}

void setUp(void) {
    create_test_file(NOTIFY_TEST_FILE);
}

void tearDown(void) {
    remove(NOTIFY_TEST_FILE);
}

void test_setup_inotify(void) {
    int inotify_fd = setup_inotify(NOTIFY_TEST_FILE);
    TEST_ASSERT_TRUE(inotify_fd >= 0);
    close(inotify_fd);
}

void test_setup_inotify_invalid_file(void) {
    int inotify_fd = setup_inotify("non_existent_file.json");
    TEST_ASSERT_TRUE(inotify_fd < 0);
}

void test_write_rules_changes(void) {
    int inotify_fd = setup_inotify(NOTIFY_TEST_FILE);
    TEST_ASSERT_TRUE(inotify_fd >= 0);
    FILE* fd = fopen(NOTIFY_TEST_FILE, "a");
    TEST_ASSERT_NOT_NULL(fd);
    fputs("TEST", fd); // trigger IN_CLOSE_WRITE event
    fclose(fd);
    struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
    int ready = poll(&pfd, 1, 1000);
    TEST_ASSERT_TRUE(ready > 0);
    int reload_needed = watch_rules_changes(inotify_fd);
    TEST_ASSERT_TRUE(reload_needed == 1);
    remove(NOTIFY_TEST_FILE); 
}

void test_moved_rules_changes(void) {
    int inotify_fd = setup_inotify(".");
    TEST_ASSERT_TRUE(inotify_fd >= 0);
    remove(NOTIFY_TEST_FILE); 
    const char* temp_source = "/tmp/temp_incoming.json";
    FILE* fd = fopen(temp_source, "w");
    TEST_ASSERT_NOT_NULL(fd);
    fputs("TEST", fd);
    fclose(fd);
    int rename_result = rename(temp_source, NOTIFY_TEST_FILE); // trigger IN_MOVED_TO event
    struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
    int ready = poll(&pfd, 1, 1000);
    TEST_ASSERT_TRUE(rename_result == 0);    
    TEST_ASSERT_TRUE(ready > 0);
    int reload_needed = watch_rules_changes(inotify_fd);
    TEST_ASSERT_TRUE(reload_needed == 1);
    close(inotify_fd);
    remove(NOTIFY_TEST_FILE);
    remove(temp_source); 
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_setup_inotify);
    RUN_TEST(test_setup_inotify_invalid_file);
    RUN_TEST(test_write_rules_changes);
    RUN_TEST(test_moved_rules_changes);
    return UNITY_END();
}