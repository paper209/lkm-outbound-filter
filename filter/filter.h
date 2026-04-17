#ifndef FILTER_H
#define FILTER_H

#include "linux/spinlock.h"

#include "filter_port.h"
#include "filter_address.h"

enum {
    FILTER_REALLOC_ERROR = -1,
};

extern spinlock_t filter_lock;

void init_filter_lock(void);

#endif
