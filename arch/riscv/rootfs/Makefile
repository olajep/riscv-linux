# check RISCV environment variable
ifndef RISCV
$(error Please set environment variable RISCV. Please take a look at README)
endif

all: rootfs

#--------------------------------------------------------------------
# Build tools
#--------------------------------------------------------------------

RISCV_PREFIX=riscv64-unknown-elf-
CC = $(RISCV_PREFIX)gcc
LD = $(RISCV_PREFIX)ld
RISCV_DUMP = $(RISCV_PREFIX)objdump
RISCV_COPY = $(RISCV_PREFIX)objcopy
RISCV_READELF = $(RISCV_PREFIX)readelf
CFLAGS = -static -Wa,-march=RVIMAFD -ffast-math -fno-builtin-printf -O2 #-fPIC
RISCV_DUMP_OPTS = -D
RISCV_LINK_OPTS = -nostdlib -nostartfiles -ffast-math #-lc -lgcc

#--------------------------------------------------------------------
# Busybox variables
#--------------------------------------------------------------------

BUSYBOX_REPO_PATH = repo/busybox
BUSYBOX_ELF_BUILD = $(BUSYBOX_REPO_PATH)/busybox
BUSYBOX_ELF = build/busybox

#--------------------------------------------------------------------
# Stream variables
#--------------------------------------------------------------------

STREAM_REPO_PATH = repo/stream
STREAM_INT_ELF = build/stream.int


#--------------------------------------------------------------------
# Busybox rules
#--------------------------------------------------------------------

$(BUSYBOX_REPO_PATH):
	mkdir -p $@
	git clone -b 1_25_stable git://git.busybox.net/busybox $@
	cp config/busybox.config $@/.config

$(BUSYBOX_ELF): $(BUSYBOX_ELF_BUILD) 
	mkdir -p $(@D)
	ln -sf $(abspath $<) $@

$(BUSYBOX_ELF_BUILD): | $(BUSYBOX_REPO_PATH)
	$(MAKE) -C $(@D)

busybox: $(BUSYBOX_ELF)

busybox-clean:
	-$(MAKE) clean -C $(BUSYBOX_REPO_PATH)
	-rm $(BUSYBOX_ELF)

.PHONY: busybox $(BUSYBOX_ELF_BUILD) busybox-clean

#--------------------------------------------------------------------
# Stream rules
#--------------------------------------------------------------------

$(STREAM_REPO_PATH):
	mkdir -p $@
	git clone https://github.com/jeffhammond/STREAM $@

$(STREAM_INT_ELF): $(STREAM_REPO_PATH)/stream.c | $(STREAM_REPO_PATH)
	mkdir -p $(@D)
	$(CC) -static -DSTREAM_ARRAY_SIZE=10000 -DNTIMES=2 -DSTREAM_TYPE=int $(STREAM_REPO_PATH)/stream.c -o $@

stream: $(STREAM_INT_ELF)

stream-clean:
	-rm $(STREAM_INT_ELF)

.PHONY: stream stream-clean

#--------------------------------------------------------------------
# Hello rules
#--------------------------------------------------------------------

HELLO_ELF = build/hello

$(HELLO_ELF): hello/hello.c
	mkdir -p $(@D)
	$(CC) -static $< -o $@

hello: $(HELLO_ELF)

.PHONY: hello

#--------------------------------------------------------------------
# Redis variables
#--------------------------------------------------------------------

REDIS_PATH = redis-4.0.2
REDIS_ELF_BUILD = $(REDIS_PATH)/src/redis-server
REDIS_ELF = build/redis-server

#--------------------------------------------------------------------
# Redis rules
#--------------------------------------------------------------------

$(REDIS_ELF): $(REDIS_ELF_BUILD)
	mkdir -p $(@D)
	ln -sf $(abspath $<) $@
	ln -sf $(abspath $(<D))/redis-benchmark $(@D)/redis-benchmark
	ln -sf $(abspath $(<D))/redis-cli $(@D)/redis-cli

$(REDIS_ELF_BUILD):
	$(MAKE) -C $(REDIS_PATH)

redis: $(REDIS_ELF)

redis-clean:
	-$(MAKE) clean -C $(REDIS_PATH)
	-rm $(REDIS_ELF)

.PHONY: redis $(REDIS_ELF_BUILD) redis-clean

#--------------------------------------------------------------------
# Rootfs top-level rules
#--------------------------------------------------------------------

rootfs: busybox stream hello

clean: busybox-clean stream-clean
	rm $(HELLO_ELF)

.PHONY: all rootfs rootfs-clean
