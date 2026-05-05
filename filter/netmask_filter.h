#ifndef NETMASKFILTER_H
#define NETMASKFILTER_H

#include <linux/ip.h>
#include <linux/types.h>

int init_netmask_filter(unsigned int max_len);
void deinit_netmask_filter(void);

int new_netmask_filter(__be32 address, __be32 mask);
void remove_netmask_filter(__be32 address, __be32 mask);

bool netmask_filter(struct iphdr *iph);

#endif
