#include <linux/kernel.h>

#include "filter.h"

void init_filters_lock(void) {
    init_port_lock();
    init_netmask_lock();
    init_signature_lock();
}

void deinit_filter(void) {
    deinit_port_filter();
    deinit_netmask_filter();
    deinit_signature_filter();
}
