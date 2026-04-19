#ifndef FILTERPORT_H
#define FILTERPORT_H

#include <linux/ip.h>
#include <linux/types.h>

void deinit_port_filter(void);
bool port_filter(struct iphdr *iph, struct sk_buff *skb);
int add_port_filter(__be16 port);
int remove_port_filter(__be16 port);

#endif
