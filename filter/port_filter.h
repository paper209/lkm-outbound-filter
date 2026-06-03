#ifndef FILTERPORT_H
#define FILTERPORT_H

#include <linux/ip.h>
#include <linux/types.h>
#include <linux/skbuff.h>

int init_port_filter(unsigned int len);
void deinit_port_filter(void);

int new_port_filter(__be16 port, __u8 protocol);
void remove_port_filter(__be16 port, __u8 protocol);
bool port_filter(__u8 protocol, __be16 port);

#endif
