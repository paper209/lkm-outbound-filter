#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/spinlock.h>

#include "filter.h"

struct filter {
    __u8 protocol;
    __be16 port;
};

spinlock_t port_lock;

struct filter *port_filters = NULL;
unsigned int port_filters_len = 0;

void init_port_lock(void) {
    spin_lock_init(&port_lock);
}

void deinit_port_filter(void) {
    spin_lock(&port_lock);
    kfree(port_filters);
    spin_unlock(&port_lock);
}

bool port_filter(struct iphdr *iph, struct sk_buff *skb) {
    struct filter packet;
    switch (iph->protocol) {
        // tcp
        case 6: {
            const struct tcphdr *tcph = tcp_hdr(skb);
            packet.protocol = 6;
            packet.port = tcph->dest;

            break;
        }

        // udp
        case 17: {
            const struct udphdr *udph = udp_hdr(skb);
            packet.protocol = 17;
            packet.port = udph->dest;

            break;
        }

        default: return false;
    }
    
    spin_lock(&port_lock);
    for (int i = 0; i < port_filters_len; i++) {
        struct filter *filter = &port_filters[i];
        if (filter->protocol == packet.protocol && filter->port == packet.port) {
            spin_unlock(&port_lock);
            return true;
        } 
    }
    spin_unlock(&port_lock);

    return false;
}

int add_port_filter(__be16 port, __u8 protocol) {
    spin_lock(&port_lock);

    struct filter *filters = krealloc(port_filters, sizeof(struct filter)*++port_filters_len, GFP_ATOMIC);
    if (!filters) {
        port_filters_len--;
        spin_unlock(&port_lock);

        return FILTER_REALLOC_ERROR;
    }
    port_filters = filters;

    port_filters[port_filters_len-1] = (struct filter){
        .protocol = protocol,
        .port = port,
    };
    printk(KERN_INFO "added port filter: %d\n", ntohs(port));
    
    spin_unlock(&port_lock);
    
    return 0;
}

int remove_port_filter(__be16 port, __u8 protocol) {
    spin_lock(&port_lock);

    for (int i = 0; i < port_filters_len; i++) {
        struct filter *filter = &port_filters[i];
        if (filter->port == port && filter->protocol == protocol) {
            port_filters_len--;
            for (int j = i; j < port_filters_len; j++) {
                port_filters[j] = port_filters[j+1];
            }

            struct filter *filters = krealloc(port_filters, sizeof(struct filter)*port_filters_len, GFP_ATOMIC);
            if (!filters) {
                spin_unlock(&port_lock);

                return FILTER_REALLOC_ERROR;
            }
            port_filters = filters;

            break;
        }
    }
    printk(KERN_INFO "removed port filter: %d\n", ntohs(port));
    
    spin_unlock(&port_lock);
    return 0;
}
