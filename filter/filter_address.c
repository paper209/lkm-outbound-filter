#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ip.h>

#include "filter.h"

__be32 *block_addrs = NULL;
unsigned int block_addrs_len = 0;

void deinit_block_address(void) {
    spin_lock(&filter_lock);
    kfree(block_addrs);
    spin_unlock(&filter_lock);
}

bool is_block_address(struct iphdr *iph) {
    spin_lock(&filter_lock);
    for (int i = 0; i < block_addrs_len; i++) {
        if (block_addrs[i] == iph->daddr) {
            spin_unlock(&filter_lock);
            return true;
        } 
    }
    spin_unlock(&filter_lock);

    return false;
}

int add_address_filter(__be32 address) {
    spin_lock(&filter_lock);

    printk(KERN_INFO "added address filter: %pI4\n", &address);
    __be32 *addrs = krealloc(block_addrs, sizeof(__be32)*++block_addrs_len, GFP_ATOMIC);
    if (!addrs) {
        block_addrs_len--;
        spin_unlock(&filter_lock);

        return FILTER_REALLOC_ERROR;
    }
    block_addrs = addrs;
    
    block_addrs[block_addrs_len-1] = address;
    spin_unlock(&filter_lock);
    
    return 0;
}

int remove_address_filter(__be32 address) {
    spin_lock(&filter_lock);

    for (int i = 0; i < block_addrs_len; i++) {
        if (block_addrs[i] == address) {
            block_addrs_len--;
            for (int j = i; j < block_addrs_len; j++) {
                block_addrs[j] = block_addrs[j+1];
            }

            __be32 *addrs = krealloc(block_addrs, sizeof(__be32)*block_addrs_len, GFP_ATOMIC);
            if (!addrs) {
                spin_unlock(&filter_lock);

                return FILTER_REALLOC_ERROR;
            }
            block_addrs = addrs;

            break;
        }
    }

    spin_unlock(&filter_lock);
    return 0;
}
