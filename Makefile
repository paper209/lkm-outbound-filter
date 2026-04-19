obj-m += filter.o
filter-objs := main.o tcp/tcp.o filter/filter.o filter/port_filter.o filter/netmask_filter.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
