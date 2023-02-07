obj-m += module.o
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PREFIX ?= /

# Example                                                                                                                                                                                                          
# Make module for currently running kernel:                                                                                                                                                                        
#     make                                                                                                                                                                                                         
#                                                                                                                                                                                                                  
# Make module for other kernel installed locally.                                                                                                                                                                  
#     make KVER=3.10.0-862.14.4.el7.x86_64                                                                                                                                                                         
#                                                                                                                                                                                                                  
# Make module for kernel which is not installed, but are installed kernel headers from kernel-devel                                                                                                                 
#     make KVER=3.10.0-862.14.4.el7.x86_64 KDIR=/usr/src/kernels/3.10.0-862.14.4.el7.x86_64                                                                                                                        
#                                                                                                                                                                                                                  
# Make module for custom kernel source                                                                                                                                                                             
#     make KVER=6.1.0-orion  KDIR=/home/example/src/kernel-6.1.0                                                                                                                                                   
#                                                       

-include version.mk

all: dwarf 

dwarf: module.c
	$(MAKE) V=1 -C $(KDIR) CONFIG_DEBUG_INFO=y M="$(PWD)" modules
	dwarfdump -di module.ko > module.dwarf
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M="$(PWD)" clean

clean:
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M="$(PWD)" clean
	rm -f module.dwarf
