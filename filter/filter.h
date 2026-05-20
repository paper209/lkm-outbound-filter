#ifndef FILTER_H
#define FILTER_H

#include <linux/skbuff.h>
#include <linux/ip.h>

#include "port_filter.h"
#include "netmask_filter.h"
#include "signature_filter.h"

// error code
enum {
    FILTER_ALLOC_ERROR = -1,
    FILTER_IS_FULL = -2,
};

// filter's state
enum filter_state {
    FILTER_USED = 1,
    FILTER_EMPTY = 0,
};

void deinit_filters(void);
int init_filters(unsigned int max_len);
void init_filters_lock(void);

bool fast_filter(struct sk_buff *skb, struct iphdr *iph);
bool slow_filter(struct sk_buff *skb, struct iphdr *iph);

#endif
