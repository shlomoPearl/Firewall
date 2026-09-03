CLANG   := clang
CC      := gcc
BPFTOOL := bpftool
CFLAGS  := -O2 -g -Wall -fno-asynchronous-unwind-tables
OUTPUT := .output
APP    := firewall
TEST_PARSER  := test_parser_runner
TEST_INOTIFY := test_inotify_runner
TEST_XDP := test_xdp_filter_runner

BPF_OBJ := $(OUTPUT)/firewall.bpf.o
SKEL    := $(OUTPUT)/firewall.skel.h
APP_OBJS := $(OUTPUT)/firewall.o \
            $(OUTPUT)/rules_parser.o \
            $(OUTPUT)/rules_notify.o \
            $(OUTPUT)/map_loader.o \
            $(OUTPUT)/cJSON.o


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

# Compile the eBPF program into a BPF object file.
$(BPF_OBJ): firewall.bpf.c vmlinux.h | $(OUTPUT)
	@echo "  CLANG   $@"
	$(CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-I. \
		-c firewall.bpf.c \
		-o $@

# Generate the libbpf skeleton header from the compiled BPF object.
# This header is what firewall.c includes to load/attach the program.
$(SKEL): $(BPF_OBJ)
	@echo "  SKEL    $@"
	$(BPFTOOL) gen skeleton $< > $@

# firewall.c needs the generated skeleton, plus the headers of the modules
# it calls into.
$(OUTPUT)/firewall.o: firewall.c config.h rules_parser.h rules_notify.h map_loader.h $(SKEL) | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) -I$(OUTPUT) -c firewall.c -o $@

$(OUTPUT)/rules_parser.o: rules_parser.c rules_parser.h config.h lib/cJSON.h | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) -c rules_parser.c -o $@

$(OUTPUT)/rules_notify.o: rules_notify.c rules_notify.h config.h | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) -c rules_notify.c -o $@

$(OUTPUT)/map_loader.o: map_loader.c map_loader.h | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) -c map_loader.c -o $@

$(OUTPUT)/cJSON.o: lib/cJSON.c lib/cJSON.h | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) -c lib/cJSON.c -o $@

# Link the daemon.
$(APP): $(APP_OBJS)
	@echo "  LINK    $@"
	$(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@

$(TEST_PARSER): tests/test_parser.o rules_parser.o map_loader.o lib/cJSON.o lib/unity.o
	@echo "  LINK    $@"
	$(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@

$(TEST_INOTIFY): tests/test_notify.o rules_notify.o lib/unity.o
	@echo "  LINK    $@"
	$(CC) $(CFLAGS) $^ -o $@

$(TEST_XDP): tests/test_xdp_filter.o lib/unity.o | $(BPF_OBJ)
	@echo "  LINK    $@"
	$(CC) $(CFLAGS) tests/test_xdp_filter.o lib/unity.o -lbpf -lelf -lz -o $@

run_parser_test: $(TEST_PARSER)
	./$(TEST_PARSER)

run_inotify_test: $(TEST_INOTIFY)
	./$(TEST_INOTIFY)

run_xdp_test: $(TEST_XDP) $(BPF_OBJ)
	sudo ./$(TEST_XDP) $(BPF_OBJ)
run_all_tests: run_parser_test run_inotify_test run_xdp_test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -c $< -o $@

lib/%.o: lib/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "  CLEAN   app + bpf build output"
	rm -rf $(OUTPUT) $(APP)

clean_tests:
	@echo "  CLEAN   test binaries and objects"
	rm -f $(TEST_PARSER) $(TEST_INOTIFY) $(TEST_XDP) *.o lib/*.o tests/*.o

clean_all: clean clean_tests

.PHONY: all clean clean_tests clean_all \
        run_parser_test run_inotify_test run_xdp_test run_all_tests
