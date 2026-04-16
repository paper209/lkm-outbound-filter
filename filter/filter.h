#ifndef FILTER_H
#define FILTER_H

#include <linux/skbuff.h>

#include "filter_port.h"

#define FILTER_REALLOC_ERROR -1

extern spinlock_t filter_lock;

void init_filter_lock(void);
bool is_block(struct iphdr *iph, struct sk_buff *skb);

#endif
