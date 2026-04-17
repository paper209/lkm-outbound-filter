#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "filter.h"

__be16 *block_ports = NULL;
unsigned int block_ports_len = 0;

bool is_block_port(struct iphdr *iph, struct sk_buff *skb) {
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
    for (int i = 0; i < block_ports_len; i++) {
        if (block_ports[i] == port) {
            spin_unlock(&filter_lock);
            return true;
        } 
    }
    spin_unlock(&filter_lock);

    return false;
}

int add_port_filter(__be16 port) {
    spin_lock(&filter_lock);

    printk(KERN_INFO "added port filter: %d\n", ntohs(port));
    __be16 *ports = krealloc(block_ports, sizeof(__be16)*++block_ports_len, GFP_ATOMIC);
    if (!ports) {
        block_ports_len--;
        spin_unlock(&filter_lock);

        return FILTER_REALLOC_ERROR;
    }
    block_ports = ports;
    
    block_ports[block_ports_len-1] = port;
    spin_unlock(&filter_lock);
    
    return 0;
}

int remove_port_filter(__be16 port) {
    spin_lock(&filter_lock);

    for (int i = 0; i < block_ports_len; i++) {
        if (block_ports[i] == port) {
            block_ports_len--;
            for (int j = i; j < block_ports_len; j++) {
                block_ports[j] = block_ports[j+1];
            }

            __be16 *ports = krealloc(block_ports, sizeof(__be16)*block_ports_len, GFP_ATOMIC);
            if (!ports) {
                spin_unlock(&filter_lock);

                return FILTER_REALLOC_ERROR;
            }
            block_ports = ports;

            break;
        }
    }

    spin_unlock(&filter_lock);
    return 0;
}
