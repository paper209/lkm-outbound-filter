#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "config.h"
#include "tcp/tcp.h"
#include "filter/filter.h"
#include "parser/parser.h"

unsigned int hook(void *pb, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *iph = ip_hdr(skb);
    if (port_filter(iph, skb) || netmask_filter(iph)) {
        printk(KERN_INFO "(1) filtered: %pI4 => %pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }
    
    switch (iph->protocol) {
        // udp
        case 17: {
            const struct udphdr *udph = udp_hdr(skb);
            if (ntohs(udph->dest) == 209 && iph->daddr == htonl(0x7F000001)) {
                parse_set_packet(skb, udph);
                return NF_DROP;
            }

            break;
        }

        // tcp
        case 6: {
            const struct tcphdr *tcph = tcp_hdr(skb);
            if (tcph->syn && !tcph->ack) {
                switch (new_tcp_session(iph, tcph)) {
                    case TCP_ALLOC_ERROR:
                        printk(KERN_ERR "tcp new connection error: alloc\n");
                        break;
                    case TCP_SESSIONS_FULL:
                        printk(KERN_ERR "tcp new connection error: sessions array is full\n");
                        break;
                }
            } else if (tcph->fin) {
                remove_tcp_session(iph, tcph);
            } else {
                switch (append_tcp_data(skb, iph, tcph)) {
                    case TCP_INVALID_LENGTH:
                        printk(KERN_ERR "tcp add data error: invalid length\n");
                        break;
                    case TCP_BUFFER_COPY_ERROR:
                        printk(KERN_ERR "tcp add data error: buffer copy\n");
                        break;
                }
            }

            break;
        }
    }

    if (signature_filter(iph, skb)) {
        printk(KERN_INFO "(2) filtered: %pI4 => %pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

const struct nf_hook_ops nfho = {
    .pf = PF_INET,
    .hook = hook,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

int init(void) {
    if (init_tcp(TCP_MAX_SESSIONS, TCP_MAX_BUFFER) == TCP_ALLOC_ERROR) {
        printk(KERN_ERR "init tcp error: alloc error\n");
        return TCP_ALLOC_ERROR;
    }

    if (init_filters(FILTER_MAX_LENGTH) == FILTER_ALLOC_ERROR) {
        printk(KERN_ERR "init filters error: alloc error\n");
        return FILTER_ALLOC_ERROR;
    }

    
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "outbound filter is loaded.\n");

    return 0;
}

void deinit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    
    deinit_filters();
    deinit_tcp();
    
    printk(KERN_INFO "outbound filter is unloaded.\n");
}

module_init(init);
module_exit(deinit);

MODULE_LICENSE("GPL");
