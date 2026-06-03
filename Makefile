obj-m += filter.o
filter-objs := main.o tcp/tcp.o filter/filter.o filter/port_filter.o filter/netmask_filter.o filter/signature_filter.o parser/set_parser.o parser/icmp_parser.o parser/tcp_parser.o parser/udp_parser.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
