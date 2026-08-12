CLANG := clang
CC := gcc
BPFTOOL := bpftool

OUTPUT := .output
BPF_OBJ := $(OUTPUT)/xdp-wall.bpf.o
SKEL := $(OUTPUT)/xdp-wall.skel.h
APP_OBJ := $(OUTPUT)/userspace.o
APP := xdp-wall

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

CFLAGS := -O2 -g -Wall -fno-asynchronous-unwind-tables

# libbpf headers
BPF_INCLUDES := -I$(OUTPUT)

.PHONY: all clean

all: $(APP)

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Compile the eBPF program
$(BPF_OBJ): xdp-wall.bpf.c xdp-tcp.h vmlinux.h | $(OUTPUT)
	@echo "  CLANG   $@"
	$(CLANG) \
		-g -O2 \
		-target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-I. \
		-c xdp-wall.bpf.c \
		-o $(BPF_OBJ)

# Generate libbpf skeleton
$(SKEL): $(BPF_OBJ)
	@echo "  SKEL    $@"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

# Compile userspace program
$(APP_OBJ): userspace.c xdp-tcp.h $(SKEL) | $(OUTPUT)
	@echo "  GCC     $@"
	$(CC) $(CFLAGS) \
		-I$(OUTPUT) \
		-c userspace.c \
		-o $(APP_OBJ)

# Link userspace program
$(APP): $(APP_OBJ)
	@echo "  LINK    $@"
	$(CC) $(CFLAGS) \
		$(APP_OBJ) \
		-lbpf \
		-lelf \
		-lz \
		-o $(APP)

clean:
	@echo "  CLEAN"
	rm -rf $(OUTPUT) $(APP)

