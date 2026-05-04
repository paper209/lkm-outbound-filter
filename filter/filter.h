#ifndef FILTER_H
#define FILTER_H

#include "port_filter.h"
#include "netmask_filter.h"
#include "signature_filter.h"

// error code
enum {
    FILTER_REALLOC_ERROR = -1,
    FILTER_ALLOC_ERROR = -2,
    FILTER_IS_FULL = -3,
};

// filter's state
enum filter_state {
    FILTER_USED = 1,
    FILTER_EMPTY = 0,
};

void deinit_filter(void);
int init_filters(unsigned int max_len);
void init_filters_lock(void);

#endif
