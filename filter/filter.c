#include <linux/kernel.h>

#include "filter.h"

// init filters
int init_filters(unsigned int max_len) {
    // init port filter
    int n = init_port_filter(max_len);
    if (n < 0) return n;

    return 0;
}

// to be removed
void init_filters_lock(void) {
    //init_port_lock();
    init_netmask_lock();
    init_signature_lock();
}

// to be updated
void deinit_filter(void) {
    deinit_port_filter();
    deinit_netmask_filter();
    deinit_signature_filter();
}
