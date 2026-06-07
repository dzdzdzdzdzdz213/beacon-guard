CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH ?= x86

KERNEL_RELEASE := $(shell uname -r 2>/dev/null || echo "6.0.0")
KERNEL_BUILD := /lib/modules/$(KERNEL_RELEASE)/build

CFLAGS := -target bpf \
		  -D__TARGET_ARCH_$(ARCH) \
		  -I$(KERNEL_BUILD)/tools/include/uapi \
		  -I$(KERNEL_BUILD)/tools/lib \
		  -I$(KERNEL_BUILD)/tools/perf \
		  -I/usr/include/x86_64-linux-gnu \
		  -Wall \
		  -O2 \
		  -g \
		  -c

SRCS := $(wildcard *.bpf.c)
OBJS := $(SRCS:.bpf.c=.bpf.o)

all: $(OBJS)

%.bpf.o: %.bpf.c common.h
	$(CLANG) $(CFLAGS) -o $@ $<
	$(LLVM_STRIP) -g $@

clean:
	rm -f *.bpf.o

install: all
	$(BPFTOOL) gen object beacon_guard.bpf.o $(OBJS)
	cp beacon_guard.bpf.o ../loader/

.PHONY: all clean install
