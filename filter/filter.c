#include <linux/kernel.h>
#include <linux/spinlock.h>

#include "filter.h"

spinlock_t filter_lock;

void init_filter_lock(void) {
    spin_lock_init(&filter_lock);
}

void deinit_filter(void) {
    deinit_block_ports();
    deinit_block_address();
}
