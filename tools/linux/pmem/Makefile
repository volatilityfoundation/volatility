obj-m += pmem.o
KDIR ?= /
KVER ?= $(shell uname -r)

-include version.mk

all: pmem 

pmem: pmem.c
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M=$(PWD) clean
