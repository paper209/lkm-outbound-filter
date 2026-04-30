#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>

#include "tcp.h"

#define TRUE 1

struct tcp_session *tcp_sessions = NULL;
unsigned int tcp_sessions_len = 0;

spinlock_t tcp_lock;

void init_tcp_lock(void) {
    spin_lock_init(&tcp_lock);
}

void deinit_tcp_sessions(void) {
    spin_lock(&tcp_lock);

    for (int i = 0; i < tcp_sessions_len; i++) {
        struct tcp_session *session = &tcp_sessions[i];    
        kfree(session->buffer);
    }

    tcp_sessions = NULL;
    tcp_sessions_len = 0;
    
    kfree(tcp_sessions);
    
    spin_unlock(&tcp_lock);
}

int add_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    struct tcp_session *sessions = krealloc(tcp_sessions, sizeof(struct tcp_session)*++tcp_sessions_len, GFP_ATOMIC);
    if (!sessions) {
        tcp_sessions_len--;
        spin_unlock(&tcp_lock);

        return TCP_REALLOC_ERROR;
    }
    tcp_sessions = sessions;
    
    tcp_sessions[tcp_sessions_len-1] = (struct tcp_session){
        .daddr = iph->daddr,
        .sport = tcph->source,
        .dport = tcph->dest,
        .init_seq = tcph->seq,
        .buffer = NULL,
        .buffer_len = 0,
    };
    spin_unlock(&tcp_lock);

    return TRUE;
}

static struct tcp_session *get_tcp_session_unlock(struct iphdr *iph, struct tcphdr *tcph) {
    for (int i = 0; i < tcp_sessions_len; i++) {
        struct tcp_session *session = &tcp_sessions[i];
        if (session->daddr == iph->daddr && session->sport == tcph->source && session->dport == tcph->dest) {
            return session;
        }
    }

    return NULL;
}

char *get_tcp_buffer(struct iphdr *iph, struct tcphdr *tcph, unsigned int *len) {
    spin_lock(&tcp_lock);
    struct tcp_session *sess = get_tcp_session_unlock(iph, tcph);
    if (!sess) {
        spin_unlock(&tcp_lock);
        return NULL;
    }

    *len = sess->buffer_len;
    char *buffer = kmalloc(*len, GFP_ATOMIC);
    if (!buffer) {
        spin_unlock(&tcp_lock);
        return NULL;
    }
    memcpy(buffer, sess->buffer, *len);
    
    spin_unlock(&tcp_lock);
    return buffer;
}

int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    for (int i = 0; i < tcp_sessions_len; i++) {
        struct tcp_session *session = &tcp_sessions[i];
        
        if (session->daddr == iph->daddr && session->sport == tcph->source && session->dport == tcph->dest) {
            kfree(session->buffer);

            for (int j = i; j < tcp_sessions_len-1; j++) {
                tcp_sessions[j] = tcp_sessions[j+1];
            }
            tcp_sessions_len--;
            struct tcp_session *sessions = krealloc(tcp_sessions, sizeof(struct tcp_session)*tcp_sessions_len, GFP_ATOMIC);
            if (sessions) tcp_sessions = sessions;

            spin_unlock(&tcp_lock);

            return TRUE;
        }
    }
    spin_unlock(&tcp_lock);

    return TCP_SESSION_NOT_FOUND;
}

int add_tcp_data(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);
    struct tcp_session *session = get_tcp_session_unlock(iph, tcph);
    if (!session) {
        spin_unlock(&tcp_lock);
        return TCP_SESSION_NOT_FOUND;
    }
    
    int data_len = ntohs(iph->tot_len)-((iph->ihl*4)+(tcph->doff*4));
    if (data_len <= 0) {
        spin_unlock(&tcp_lock);
        return TCP_INVALID_LENGTH;
    }

    int offset = ntohl(tcph->seq)-ntohl(session->init_seq)-1;
    if (offset < 0) offset = 0;
    
    if (offset+data_len > session->buffer_len) {
        char *buffer = krealloc(session->buffer, offset+data_len, GFP_ATOMIC);
        if (!buffer) {
            spin_unlock(&tcp_lock);
            return TCP_REALLOC_ERROR;
        }

        session->buffer = buffer;
        session->buffer_len = offset+data_len;
    }

    int data_offset = ((char *)tcph+tcph->doff*4)-(char *)skb->data;
    if (skb_copy_bits(skb, data_offset, session->buffer+offset, data_len) < 0) {
        spin_unlock(&tcp_lock);
        return TCP_BUFFER_COPY_ERROR;
    } 
    spin_unlock(&tcp_lock);

    return TRUE;
}
