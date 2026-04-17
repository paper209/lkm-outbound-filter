#ifndef FILTERADDRESS_H
#define FILTERADDRESS_H

#include <linux/ip.h>
#include <linux/types.h>

void deinit_block_address(void);

bool is_block_address(struct iphdr *iph);
int add_address_filter(__be32 address);
int remove_address_filter(__be32 address);

#endif
