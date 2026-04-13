#ifndef TCP_H
#define TCP_H

#include <linux/ip.h>
#include <linux/tcp.h>

void init_tcp_lock(void);
void deinit_tcp_sessions(void);
int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_data(struct iphdr *iph, struct tcphdr *tcph);

#endif
