#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "filter.h"

__be16 *port_filters = NULL;
unsigned int port_filters_len = 0;

void deinit_port_filter(void) {
    spin_lock(&filter_lock);
    kfree(port_filters);
    spin_unlock(&filter_lock);
}

bool port_filter(struct iphdr *iph, struct sk_buff *skb) {
    __be16 port;
    switch (iph->protocol) {
        case 6: {
            const struct tcphdr *tcph = tcp_hdr(skb);
            port = tcph->dest;

            break;
        }
        default: return false;
    }
    
    spin_lock(&filter_lock);
    for (int i = 0; i < port_filters_len; i++) {
        if (port_filters[i] == port) {
            spin_unlock(&filter_lock);
            return true;
        } 
    }
    spin_unlock(&filter_lock);

    return false;
}

int add_port_filter(__be16 port) {
    spin_lock(&filter_lock);

    __be16 *ports = krealloc(port_filters, sizeof(__be16)*++port_filters_len, GFP_ATOMIC);
    if (!ports) {
        port_filters_len--;
        spin_unlock(&filter_lock);

        return FILTER_REALLOC_ERROR;
    }
    port_filters = ports;

    port_filters[port_filters_len-1] = port;
    printk(KERN_INFO "added port filter: %d\n", ntohs(port));
    
    spin_unlock(&filter_lock);
    
    return 0;
}

int remove_port_filter(__be16 port) {
    spin_lock(&filter_lock);

    for (int i = 0; i < port_filters_len; i++) {
        if (port_filters[i] == port) {
            port_filters_len--;
            for (int j = i; j < port_filters_len; j++) {
                port_filters[j] = port_filters[j+1];
            }

            __be16 *ports = krealloc(port_filters, sizeof(__be16)*port_filters_len, GFP_ATOMIC);
            if (!ports) {
                spin_unlock(&filter_lock);

                return FILTER_REALLOC_ERROR;
            }
            port_filters = ports;

            break;
        }
    }
    printk(KERN_INFO "removed port filter: %d\n", ntohs(port));
    
    spin_unlock(&filter_lock);
    return 0;
}
