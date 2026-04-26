#ifndef TCP_H
#define TCP_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

enum {
    TCP_ALLOC_ERROR = -1,
    TCP_REALLOC_ERROR = -2,
    TCP_SESSION_NOT_FOUND = -3,
    TCP_INVALID_LENGTH = -4,
    TCP_BUFFER_COPY_ERROR = -5,
};

struct tcp_session {
    __be32 daddr;
    __be16 sport;
    __be16 dport;

    __be32 init_seq;

    char *buffer;
    unsigned int buffer_len;
};

void init_tcp_lock(void);
void deinit_tcp_sessions(void);
int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int add_tcp_data(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);
char *get_tcp_buffer(struct iphdr *iph, struct tcphdr *tcph, unsigned int *len);

#endif
