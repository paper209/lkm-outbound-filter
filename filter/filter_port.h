#ifndef FILTERPORT_H
#define FILTERPORT_H

#include <linux/types.h>

bool is_block_port(struct iphdr *iph, struct sk_buff *skb);
int add_port_filter(__be16 port);
int remove_port_filter(__be16 port);

#endif
