SHELL:=/usr/bin/env bash

CLANG=clang
LINK=llvm-link
LLC=llc

DEBUG_FLAGS = -DOPTI_DEBUG -g

# Detect native architecture.
NATIVE_ARCH:=$(shell uname -m)

ifeq ($(NATIVE_ARCH),x86_64)
NATIVE_ARCH:=x86
else ifneq (,$(filter $(NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH:=arm64
else
$(error Unsupported architecture: $(NATIVE_ARCH))
endif

# This can be passed-in, valid values are: x86, arm64.
target_arch ?= $(NATIVE_ARCH)

# Set default values.
TARGET_ARCH = $(target_arch)
TRACER_NAME = tracer.ebpf.$(TARGET_ARCH)

ifeq ($(TARGET_ARCH),arm64)
TARGET_FLAGS = -target aarch64-linux-gnu
else
TARGET_FLAGS = -target x86_64-linux-gnu
endif

FLAGS=$(TARGET_FLAGS) \
	-nostdinc \
	-nostdlib \
	-ffreestanding \
	-O2 -emit-llvm -c $< \
	-Wall -Wextra -Werror \
	-Wno-address-of-packed-member \
	-Wno-unused-label \
	-Wno-unused-parameter \
	-Wno-sign-compare \
	-fno-stack-protector \
	-fno-jump-tables -DOPTI_DEBUG -g

SRCS := $(wildcard *.ebpf.c)
OBJS := $(SRCS:.c=.o)

.DEFAULT_GOAL := all

all: $(TRACER_NAME)

debug: TARGET_FLAGS+=$(DEBUG_FLAGS)
debug: all

x86:
	$(MAKE) target_arch=x86 all

arm64:
	$(MAKE) target_arch=arm64 all

debug-x86:
	$(MAKE) target_arch=x86 debug

debug-arm64:
	$(MAKE) target_arch=arm64 debug

%.ebpf.c: errors.h ;

%.ebpf.o: %.ebpf.c
	$(CLANG) $(FLAGS) -o $@

$(TRACER_NAME): $(OBJS)
	$(LINK) $^ -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@
	@./print_instruction_count.sh $@

baseline: $(TRACER_NAME)
	cp $< $(TRACER_NAME).$@

bloatcheck: $(TRACER_NAME)
	python3 bloat-o-meter $(TRACER_NAME).baseline $(TRACER_NAME)

clean:
	rm -f *.o $(TRACER_NAME) $(TRACER_NAME).*
