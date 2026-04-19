#include <linux/kernel.h>
#include <linux/spinlock.h>

#include "filter.h"

spinlock_t filter_lock;

void init_filter_lock(void) {
    spin_lock_init(&filter_lock);
}

void deinit_filter(void) {
    deinit_port_filter();
    deinit_netmask_filter();
}
