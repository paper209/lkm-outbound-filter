#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>

#include "tcp_parser.h"
#include "../tcp/tcp.h"
#include "../filter/filter.h"

// parse tcp packet
unsigned int parse_tcp(struct iphdr *iph, struct sk_buff *skb) {
    const struct tcphdr *tcph = tcp_hdr(skb);

    if (port_filter(iph->protocol, tcph->dest)) {
        printk(KERN_INFO "outbound filter: port: tcp: %d\n", htons(tcph->dest));
        return NF_DROP;
    }

    if (tcph->syn && !tcph->ack) {
        switch (new_tcp_session(iph, tcph)) {
            case TCP_ALLOC_ERROR:
                printk(KERN_ERR "tcp new connection error: alloc\n");
                return NF_ACCEPT;
            case TCP_SESSIONS_FULL:
                printk(KERN_ERR "tcp new connection error: sessions array is full\n");
                return NF_ACCEPT;
        }
    } else if (tcph->fin || tcph->rst) {
        remove_tcp_session(iph, tcph);
    } else {
        switch (append_tcp_data(skb, iph, tcph)) {
            case TCP_INVALID_LENGTH:
                printk(KERN_ERR "tcp add data error: invalid length\n");
                return NF_ACCEPT;
            case TCP_BUFFER_COPY_ERROR:
                printk(KERN_ERR "tcp add data error: buffer copy\n");
                return NF_ACCEPT;
        }
    }

    unsigned int len = 0;
    char *buf = fetch_tcp_buffer(iph, tcph, &len);
    if (!buf) {
        return NF_ACCEPT;
    }

    if (signature_filter(buf, len)) {
        printk(KERN_INFO "outbound filter: signature: %pI4\n", &iph->daddr);
        kfree(buf);
        return NF_DROP;
    }
    kfree(buf);

    return NF_ACCEPT;
}
