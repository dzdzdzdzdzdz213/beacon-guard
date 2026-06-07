CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH ?= x86

# Kali doesn't ship kernel build headers, so use system libbpf + vmlinux.h (CO-RE)
CFLAGS := -target bpf \
		  -D__TARGET_ARCH_$(ARCH) \
		  -I. \
		  -I/usr/include \
		  -I/usr/include/x86_64-linux-gnu \
		  -Wall \
		  -O2 \
		  -g \
		  -c

SRCS := $(wildcard *.bpf.c)
OBJS := $(SRCS:.bpf.c=.bpf.o)

all: $(OBJS)

%.bpf.o: %.bpf.c vmlinux.h common.h
	$(CLANG) $(CFLAGS) -o $@ $<
	$(LLVM_STRIP) -g $@

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f *.bpf.o vmlinux.h

install: all
	$(BPFTOOL) gen object beacon_guard.bpf.o $(OBJS)
	cp beacon_guard.bpf.o ../loader/

.PHONY: all clean install
