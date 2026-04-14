#ifndef TCP_H
#define TCP_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

#define TCP_ALLOC_ERROR -1
#define TCP_REALLOC_ERROR -2
#define TCP_SESSION_NOT_FOUND -3
#define TCP_INVALID_LENGTH -4
#define TCP_BUFFER_COPY_ERROR -5

void init_tcp_lock(void);
void deinit_tcp_sessions(void);
int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_data(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);

#endif
