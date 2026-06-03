#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <linux/ip.h>
#include <linux/skbuff.h>

unsigned int parse_tcp(struct iphdr *iph, struct sk_buff *skb);

#endif
