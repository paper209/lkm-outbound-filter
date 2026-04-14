#ifndef TCP_H
#define TCP_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

void init_tcp_lock(void);
void deinit_tcp_sessions(void);
int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_data(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);

#endif
