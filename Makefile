CLANG := clang
CC := gcc
CFLAGS := -O2 -g -Wall -fno-asynchronous-unwind-tables
BPFTOOL := bpftool

OUTPUT := .output
BPF_OBJ := $(OUTPUT)/firewall.bpf.o
SKEL := $(OUTPUT)/firewall.skel.h
FIREWALL_OBJ := $(OUTPUT)/firewall.o
RULES_PARSER_OBJ := $(OUTPUT)/rules_parser.o
RULES_NOTIFY_OBJ := $(OUTPUT)/rules_notify.o
CJSON_OBJ := $(OUTPUT)/cJSON.o
APP := firewall
ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
	BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
	BPF_ARCH := arm64
else ifeq ($(ARCH),arm64)
	BPF_ARCH := arm64
else
	$(error Unsupported architecture: $(ARCH))
endif



all: $(APP)


$(OUTPUT):
	mkdir -p $(OUTPUT)

# Compile the eBPF program
$(BPF_OBJ): firewall.bpf.c vmlinux.h | $(OUTPUT)
	@echo "  CLANG   $@"
	$(CLANG) \
		-g -O2 \
		-target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-I. \
		-c firewall.bpf.c \
		-o $(BPF_OBJ)

# Generate libbpf skeleton
$(SKEL): $(BPF_OBJ)
	@echo "  SKEL    $@"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

# Compile firwall.c program
$(FIREWALL_OBJ): firewall.c lib/cJSON.h lib/cJSON.c config.h rules_parser.c rules_notify.c $(SKEL) | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) \
		-I$(OUTPUT) \
		-c firewall.c\
		-o $(FIREWALL_OBJ)
$(RULES_PARSER_OBJ): rules_parser.c lib/cJSON.h lib/cJSON.c config.h | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) \
		-c rules_parser.c \
		-o $(RULES_PARSER_OBJ)
$(RULES_NOTIFY_OBJ): rules_notify.c config.h | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) \
		-c rules_notify.c \
		-o $(RULES_NOTIFY_OBJ)
$(CJSON_OBJ): lib/cJSON.c lib/cJSON.h | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) \
		-c lib/cJSON.c \
		-o $(CJSON_OBJ)

# Link firewall program
$(APP): $(FIREWALL_OBJ) $(RULES_PARSER_OBJ) $(RULES_NOTIFY_OBJ) $(CJSON_OBJ)
	@echo "  LINK    $@"
	$(CC) $(CFLAGS) \
		$(FIREWALL_OBJ) \
		$(RULES_PARSER_OBJ) \
		$(RULES_NOTIFY_OBJ) \
		$(CJSON_OBJ) \
		-lbpf \
		-lelf \
		-lz \
		-o $(APP)

test_all: $(TEST_PARSER) $(TEST_INOTIFY)
	./$(TEST_PARSER)
	./$(TEST_INOTIFY)

UNITY_SRC = unity.c
TEST_PARSER = test_parser_runner
TEST_INOTIFY = test_inotify_runner

run_all_tests: $(TEST_PARSER) $(TEST_INOTIFY)
	./$(TEST_PARSER)
	./$(TEST_INOTIFY)

run_parser_test: $(TEST_PARSER)
	./$(TEST_PARSER)

run_inotify_test: $(TEST_INOTIFY)
	./$(TEST_INOTIFY)


$(TEST_PARSER): tests/test_parser.o rules_parser.o lib/cJSON.o lib/unity.o 
	$(CC) $(CFLAGS) $^ -o $@

$(TEST_INOTIFY): tests/test_notify.o rules_notify.o lib/unity.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -c $< -o $@

lib/%.o: lib/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean_tests:
	rm -f $(TEST_PARSER) $(TEST_INOTIFY) *.o lib/*.o tests/*.o

clean:
	@echo "  CLEAN"
	rm -rf $(OUTPUT) $(APP)

.PHONY: all clean clean_tests run_parser_test run_inotify_test run_all_tests