#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#include "filter.h"

// init filters
int init_filters(unsigned int max_len) {
    // init port filter
    int n = init_port_filter(max_len);
    if (n < 0) return n;

    // init netmask filter
    n = init_netmask_filter(max_len);
    if (n < 0) return n;

    // init signature filter
    n = init_signature_filter(max_len);
    if (n < 0) return n;

    return 0;
}

void deinit_filters(void) {
    deinit_port_filter();
    deinit_netmask_filter();
    deinit_signature_filter();
}
