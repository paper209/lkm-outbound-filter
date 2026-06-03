#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/spinlock.h>

#include "filter.h"

// port filter
struct filter {
    __u8 protocol;
    __be16 port;

    enum filter_state state;
};

static spinlock_t port_lock;

static struct filter *filters = NULL; // port filters array
static unsigned int max_filters_len = 0; // max port filters length

// init port spinlock
static void init_port_lock(void) {
    spin_lock_init(&port_lock);
}

// init port filters array and spinlock
int init_port_filter(unsigned int len) {
    init_port_lock();    
    spin_lock(&port_lock);

    max_filters_len = len; // set max filters length
    filters = kcalloc(max_filters_len, sizeof(struct filter), GFP_ATOMIC);
    if (!filters) {
        spin_unlock(&port_lock);
        return FILTER_ALLOC_ERROR;
    }

    spin_unlock(&port_lock);
    return 0;
}

// deinit port filters array
void deinit_port_filter(void) {
    spin_lock(&port_lock);
    kfree(filters);
    spin_unlock(&port_lock);
}

// find free index on filters array
static int find_free_index(__be16 port, __u8 protocol) {
    // calculate minimum start index number
    unsigned int min = (ntohs(port)+protocol)%max_filters_len;
    
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

// add new port filter
int new_port_filter(__be16 port, __u8 protocol) {
    spin_lock(&port_lock);

    // find a free index
    int i = find_free_index(port, protocol);
    if (i < 0) {
        spin_unlock(&port_lock);
        return i;
    }

    // add filters array
    filters[i] = (struct filter) {
        .port = port,
        .protocol = protocol,
        .state = FILTER_USED,
    };

    // debug
    printk(KERN_INFO "added port filter: %d\n", ntohs(port));

    spin_unlock(&port_lock);
    return 0;
}

// remove port filter to filters's array
void remove_port_filter(__be16 port, __u8 protocol) {
    spin_lock(&port_lock);
    
    // calculate minimum start index number
    unsigned int min = (ntohs(port)+protocol)%max_filters_len;
    for (int i = min; i < max_filters_len; i++) {
        struct filter *f = &filters[i];
        if (f->protocol == protocol && f->port == port) {
            memset(f, 0, sizeof(struct filter));
            break;
        }
    }

    // debug
    printk(KERN_INFO "removed port filter: %d\n", ntohs(port));

    spin_unlock(&port_lock);
}

// check the port filters
bool port_filter(__u8 protocol, __be16 port) {    
    // calculate minimum start index number
    unsigned int min = (ntohs(port)+protocol)%max_filters_len;
    spin_lock(&port_lock);

    // check the port filters
    for (int i = min; i < max_filters_len; i++) {
        struct filter *f = &filters[i];

        if (f->state == FILTER_USED) {
            if (f->protocol == protocol && f->port == port) {
                spin_unlock(&port_lock);
                return true;
            } 
        }

    }
    spin_unlock(&port_lock);

    return false;
}
