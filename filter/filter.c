#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "filter.h"

spinlock_t filter_lock;

void init_filter_lock(void) {
    spin_lock_init(&filter_lock);
}

bool is_block(struct iphdr *iph, struct sk_buff *skb) {
    switch (iph->protocol) {
        case 6: {
            struct tcphdr *tcph = tcp_hdr(skb);
            if (is_block_port(tcph->dest)) {
                return true;
            }

            break;
        }
    }

    return false;
}
