#ifndef NETMASKFILTER_H
#define NETMASKFILTER_H

#include <linux/ip.h>
#include <linux/types.h>

void init_netmask_lock(void);
void deinit_netmask_filter(void);
bool netmask_filter(struct iphdr *iph);
int add_netmask_filter(__be32 address, __be32 mask);
int remove_netmask_filter(__be32 address, __be32 mask);

#endif
