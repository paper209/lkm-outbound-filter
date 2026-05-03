#ifndef FILTER_H
#define FILTER_H

#include "port_filter.h"
#include "netmask_filter.h"
#include "signature_filter.h"

enum {
    FILTER_REALLOC_ERROR = -1,
    FILTER_ALLOC_ERROR = -2,
};

void deinit_filter(void);
void init_filters_lock(void);

#endif
