#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/spinlock.h>

#include "filter.h"

struct filter {
    __be32 address;
    __be32 mask;
};

spinlock_t netmask_lock;

struct filter *netmask_filters = NULL;
unsigned int netmask_filters_len = 0;

void init_netmask_lock(void) {
    spin_lock_init(&netmask_lock);
}

void deinit_netmask_filter(void) {
    spin_lock(&netmask_lock);
    kfree(netmask_filters);
    spin_unlock(&netmask_lock);
}

bool netmask_filter(struct iphdr *iph) {
    spin_lock(&netmask_lock);
    for (int i = 0; i < netmask_filters_len; i++) {
        struct filter *filter = &netmask_filters[i];
        if ((filter->address&filter->mask) == (iph->daddr&filter->mask)) {
            spin_unlock(&netmask_lock);
            return true;
        } 
    }
    spin_unlock(&netmask_lock);

    return false;
}

int add_netmask_filter(__be32 address, __be32 mask) {
    spin_lock(&netmask_lock);

    struct filter *filters = krealloc(netmask_filters, sizeof(struct filter)*++netmask_filters_len, GFP_ATOMIC);
    if (!filters) {
        netmask_filters_len--;
        spin_unlock(&netmask_lock);

        return FILTER_REALLOC_ERROR;
    }
    netmask_filters = filters;
    netmask_filters[netmask_filters_len-1] = (struct filter){
        .address = address,
        .mask = mask,
    };

    printk(KERN_INFO "added address filter: %pI4\n", &address);
    
    spin_unlock(&netmask_lock);
    
    return 0;
}

int remove_netmask_filter(__be32 address, __be32 mask) {
    spin_lock(&netmask_lock);

    for (int i = 0; i < netmask_filters_len; i++) {
        struct filter *filter = &netmask_filters[i];
        if (filter->address == address && filter->mask == mask) {
            netmask_filters_len--;
            for (int j = i; j < netmask_filters_len; j++) {
                netmask_filters[j] = netmask_filters[j+1];
            }

            struct filter *filters = krealloc(netmask_filters, sizeof(struct filter)*netmask_filters_len, GFP_ATOMIC);
            if (!filters) {
                netmask_filters_len++;
                spin_unlock(&netmask_lock);

                return FILTER_REALLOC_ERROR;
            }
            netmask_filters = filters;

            break;
        }
    }
    printk(KERN_INFO "removed netmask filter: %pI4\n", &address);
    
    spin_unlock(&netmask_lock);
    
    return 0;
}
