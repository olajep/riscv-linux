# Top level makefile, the real shit is at src/Makefile

CROSS_COMPILE ?= riscv64-unknown-linux-gnu-

default: all

.DEFAULT:
	$(MAKE) -C deps $@ CROSS_COMPILE=$(CROSS_COMPILE)
	$(MAKE) -C src $@ CROSS_COMPILE=$(CROSS_COMPILE)

.PHONY: install
