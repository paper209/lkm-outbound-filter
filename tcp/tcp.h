#ifndef TCP_H
#define TCP_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

enum {
    TCP_ALLOC_ERROR = -1,
    TCP_SESSION_NOT_FOUND = -2,
    TCP_INVALID_LENGTH = -3,
    TCP_BUFFER_COPY_ERROR = -4,
    TCP_SESSIONS_FULL = -5,
};

enum session_state {
    SESSION_EMPTY = 0,
    SESSION_USED = 1,
};

struct tcp_session {
    __be32 daddr;
    __be16 sport;
    __be16 dport;

    __be32 init_seq;

    char *buffer;
    unsigned int buffer_used;

    enum session_state state;
};

int init_tcp(unsigned int max_sessions, unsigned int max_buffer);
void deinit_tcp(void);
char *fetch_tcp_buffer(struct iphdr *iph, struct tcphdr *tcph, unsigned int *len);
int append_tcp_data(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);
int new_tcp_session(struct iphdr *iph, struct tcphdr *tcph);
int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph);

#endif
