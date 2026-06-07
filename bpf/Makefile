CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH ?= x86

CFLAGS := -target bpf \
		  -D__TARGET_ARCH_$(ARCH) \
		  -I. \
		  -I/usr/include \
		  -I/usr/include/x86_64-linux-gnu \
		  -Wall \
		  -O2 \
		  -g \
		  -c

all: beacon_guard.bpf.o

beacon_guard.bpf.o: beacon_guard.bpf.c vmlinux.h common.h
	$(CLANG) $(CFLAGS) -o $@ $<
	$(LLVM_STRIP) -g $@

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f *.bpf.o vmlinux.h

install: all
	cp beacon_guard.bpf.o ../loader/

.PHONY: all clean install
