#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/spinlock.h>

#include "filter.h"

// netmask filter
struct filter {
    __be32 address;
    __be32 mask;

    enum filter_state state;
};

static spinlock_t netmask_lock;

static struct filter *filters = NULL; // netmask filters array
static unsigned int max_filters_len = 0; // netmask filters max length

// init netmask spinlock
static void init_netmask_lock(void) {
    spin_lock_init(&netmask_lock);
}

// init netmask filters array and spinlock
int init_netmask_filter(unsigned int max_len) {
    init_netmask_lock();
    spin_lock(&netmask_lock);

    max_filters_len = max_len;
    filters = kcalloc(max_filters_len, sizeof(struct filter), GFP_ATOMIC);
    if (!filters) {
        spin_unlock(&netmask_lock);
        return FILTER_ALLOC_ERROR;
    }

    spin_unlock(&netmask_lock);
    return 0;
}

// deinit netmask filters array
void deinit_netmask_filter(void) {
    spin_lock(&netmask_lock);
    kfree(filters);
    spin_unlock(&netmask_lock);
}

// find free index on netmask filters array
static int find_free_index(__be32 address) {
    // calculate minimum start index number
    unsigned int min = ntohl(address)%max_filters_len;
    
    // find free index number and return
    for (int i = min; i < max_filters_len; i++) {
        struct filter *f = &filters[i];
        if (f->state == FILTER_EMPTY) {
            return i;
        }
    }

    // find free index number failed
    return FILTER_IS_FULL;
}

// add new netmask filter
int new_netmask_filter(__be32 address, __be32 mask) {
    spin_lock(&netmask_lock);
    
    // find free index
    int i = find_free_index(address);
    if (i < 0) {
        spin_unlock(&netmask_lock);
        return i;
    }

    // add filter
    filters[i] = (struct filter) {
        .address = address,
        .mask = mask,
        .state = FILTER_USED,
    };

    // debug
    printk(KERN_INFO "added netmask filter: %pI4, %pI4\n", &address, &mask);

    spin_unlock(&netmask_lock);
    return 0;
}

// remove netmask filter
void remove_netmask_filter(__be32 address, __be32 mask) {
    spin_lock(&netmask_lock);
    
    // calculate minimum start index number
    unsigned int min = ntohl(address)%max_filters_len;
    for (int i = min; i < max_filters_len; i++) {
        struct filter *f = &filters[i];
        if (f->address == address && f->mask == mask) {
            memset(f, 0, sizeof(struct filter));
            break;
        }
    }

    // debug
    printk(KERN_INFO "removed netmask filter: %pI4, %pI4\n", &address, &mask);
    spin_unlock(&netmask_lock);
}

// check the netmask filter
bool netmask_filter(struct iphdr *iph) {
    // calculate minimum start index number
    unsigned int min = ntohl(iph->daddr)%max_filters_len;
    spin_lock(&netmask_lock);

    // check the port filters
    for (int i = min; i < max_filters_len; i++) {
        struct filter *f = &filters[i];
        if ((f->address&f->mask) == (iph->daddr&f->mask)) {
            spin_unlock(&netmask_lock);
            return true;
        } 
    }
    spin_unlock(&netmask_lock);

    return false;
}
