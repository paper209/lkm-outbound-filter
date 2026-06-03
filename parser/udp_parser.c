#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "set_parser.h"
#include "udp_parser.h"
#include "../filter/filter.h"
#include "../config.h"

unsigned int parse_udp(struct iphdr *iph, struct sk_buff *skb) {
    // check the is it setting packet
    const struct udphdr *udph = udp_hdr(skb);
    if (ntohs(udph->dest) == SET_PORT && iph->daddr == htonl(SET_ADDR)) {
        parse_set_packet(skb, udph);
        return NF_DROP;
    }

    if (port_filter(iph->protocol, udph->dest)) {
        return NF_DROP;
    }

    int buffer_len = ntohs(udph->len)-sizeof(struct udphdr);
    if (buffer_len <= 0) return NF_ACCEPT;

    char *buf = kmalloc(buffer_len, GFP_ATOMIC);
    if (!buf) return NF_ACCEPT;

    int data_offset = (char *)(udph+1)-(char *)skb->data;
    if (skb_copy_bits(skb, data_offset, buf, buffer_len) < 0) {
        kfree(buf);
        return NF_ACCEPT;
    }

    if (signature_filter(buf, buffer_len)) {
        kfree(buf);
        return NF_DROP;
    }
    kfree(buf);

    return NF_ACCEPT;
}
