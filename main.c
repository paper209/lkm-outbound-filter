#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "tcp/tcp.h"
#include "filter/filter.h"

enum {
    SET_PORT_FILTER = 0,
    REMOVE_PORT_FILTER = 1,

    SET_NETMASK_FILTER = 2,
    REMOVE_NETMASK_FILTER = 3,
};

void parse_set_packet(struct sk_buff *skb, const struct udphdr *udph) {
    int data_len = ntohs(udph->len)-sizeof(struct udphdr);
    if (data_len < 1) return;
    
    char *data_buffer = kmalloc(data_len, GFP_ATOMIC);
    if (!data_buffer) return;

    int data_offset = (char *)(udph+1)-(char *)skb->data;
    if (skb_copy_bits(skb, data_offset, data_buffer, data_len) < 0) {
        kfree(data_buffer);
        return;
    }

    switch (data_buffer[0]) {
        // [type(1byte)][protocol (1byte)][port(2byte)]
        case REMOVE_PORT_FILTER:
        case SET_PORT_FILTER: {
            if (data_len == 4) {
                __u8 protocol;
                memcpy(&protocol, data_buffer+1, sizeof(protocol));

                __be16 port;
                memcpy(&port, data_buffer+2, sizeof(port));

                if (data_buffer[0] == SET_PORT_FILTER) {
                    if (add_port_filter(port, protocol) == FILTER_REALLOC_ERROR) {
                        printk(KERN_ERR "set port filter error: realloc\n");
                    }
                } else {
                    if (remove_port_filter(port, protocol) == FILTER_REALLOC_ERROR) {
                        printk(KERN_ERR "remove port filter error: realloc\n");
                    }
                }
            }

            break;
        }

        // [type(1byte)][address(4byte)][mask(4byte)]
        case REMOVE_NETMASK_FILTER:
        case SET_NETMASK_FILTER: {
            if (data_len == 9) {
                __be32 address, mask;
                memcpy(&address, data_buffer+1, sizeof(address));
                memcpy(&mask, data_buffer+5, sizeof(mask));

                if (data_buffer[0] == SET_NETMASK_FILTER) {
                    if (add_netmask_filter(address, mask) == FILTER_REALLOC_ERROR) {
                        printk(KERN_ERR "set address filter error: realloc\n");
                    }
                } else {
                    if (remove_netmask_filter(address, mask) == FILTER_REALLOC_ERROR) {
                        printk(KERN_ERR "remove address filter error: realloc\n");
                    }
                }
            }

            break;
        }
    }

    kfree(data_buffer); 
}

unsigned int hook(void *pb, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *iph = ip_hdr(skb);
    if (port_filter(iph, skb) || netmask_filter(iph)) {
        printk(KERN_INFO "filtered: %pI4 => %pI4\n", &iph->saddr, &iph->daddr);
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
                switch (add_tcp_session(iph, tcph)) {
                    case TCP_ALLOC_ERROR:
                        printk(KERN_ERR "tcp new connection error: alloc\n");
                        break;
                    case TCP_REALLOC_ERROR:
                        printk(KERN_ERR "tcp new connection error: realloc\n");
                        break;
                }
            } else if (tcph->fin) {
                remove_tcp_session(iph, tcph);
            } else {
                switch (add_tcp_data(skb, iph, tcph)) {
                    case TCP_REALLOC_ERROR:
                        printk(KERN_ERR "tcp add data error: realloc\n");
                        break;
                    case TCP_BUFFER_COPY_ERROR:
                        printk(KERN_ERR "tcp add data error: buffer copy\n");
                        break;
                }
            }

            break;
        }
    }

    return NF_ACCEPT;
}

const struct nf_hook_ops nfho = {
    .pf = PF_INET,
    .hook = hook,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

void init_locks(void) {
    init_tcp_lock();
    init_filter_lock();
}

int init(void) {
    init_locks();
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "outbound filter is loaded.\n");

    return 0;
}

void deinit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    
    deinit_filter();
    deinit_tcp_sessions();
    
    printk(KERN_INFO "outbound filter is unloaded.\n");
}

module_init(init);
module_exit(deinit);

MODULE_LICENSE("GPL");
