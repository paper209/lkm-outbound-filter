#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>

#include "icmp_parser.h"
#include "../filter/filter.h"

unsigned int parse_icmp(struct iphdr *iph, struct sk_buff *skb) {
    const struct icmphdr *icmph = icmp_hdr(skb);
    if (icmph->type == 0 || icmph->type == 8) {
        int buffer_len = ntohs(iph->tot_len)-((iph->ihl*4)+sizeof(struct icmphdr));
        if (buffer_len <= 0) return NF_ACCEPT;

        char *buf = kmalloc(buffer_len, GFP_ATOMIC);
        if (!buf) return NF_ACCEPT;

        int data_offset = (char *)(icmph+1)-(char *)skb->data;
        if (skb_copy_bits(skb, data_offset, buf, buffer_len) < 0) {
            kfree(buf);
            return NF_ACCEPT;
        }

        if (signature_filter(buf, buffer_len)) {
            kfree(buf);
            return NF_DROP;
        }
        kfree(buf);
    }

    return NF_ACCEPT;
}
