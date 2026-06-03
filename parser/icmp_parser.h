#ifndef ICMP_PARSER_H
#define ICMP_PARSER_H

#include <linux/ip.h>
#include <linux/skbuff.h>

unsigned int parse_icmp(struct iphdr *iph, struct sk_buff *skb);

#endif
