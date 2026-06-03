#ifndef UDP_PARSER_H
#define UDP_PARSER_H

unsigned int parse_udp(struct iphdr *iph, struct sk_buff *skb);

#endif
