#ifndef PARSER_H
#define PARSER_H

#include <linux/skbuff.h>
#include <linux/udp.h>

enum {
    SET_PORT_FILTER = 0,
    REMOVE_PORT_FILTER = 1,

    SET_NETMASK_FILTER = 2,
    REMOVE_NETMASK_FILTER = 3,

    SET_SIGNATURE_FILTER = 4,
    REMOVE_SIGNATURE_FILTER = 5,
};

void parse_set_packet(struct sk_buff *skb, const struct udphdr *udph);

#endif
