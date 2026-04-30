#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/slab.h>

#include "tcp.h"
 
spinlock_t tcp_lock;

struct tcp_session *tcp_sessions = NULL;
unsigned int max_tcp_sessions = 0;

// init spin lock
static void init_tcp_lock(void) {
    spin_lock_init(&tcp_lock);
}

// init tcp sessions size of max tcp sessions
static int init_tcp_sessions(unsigned int max_sessions) {
    spin_lock(&tcp_lock);
    max_tcp_sessions = max_sessions;
    tcp_sessions = kcalloc(max_sessions, sizeof(struct tcp_session), GFP_ATOMIC);
    if (!tcp_sessions) {
        spin_unlock(&tcp_lock);
        return TCP_ALLOC_ERROR;
    }
    spin_unlock(&tcp_lock);

    return 0;
}

/// init spin lock and tcp sessions array
int init_tcp(unsigned int max_sessions) {
    init_tcp_lock();
    return init_tcp_sessions(max_sessions);
}

// deinit tcp sessions array
void deinit_tcp(void) {
    spin_lock(&tcp_lock);

    for (int i = 0; i < max_tcp_sessions; i++) {
        struct tcp_session *sess = &tcp_sessions[i];
        kfree(sess->buffer);
    }
    kfree(tcp_sessions);

    spin_unlock(&tcp_lock);
}

// find free index number on tcp sessions array
static int find_free_index(__be16 sport) {
    // minimum start index number
    unsigned int min = ntohs(sport)%max_tcp_sessions;
    
    // find free index number and return
    for (int i = min; i < max_tcp_sessions; i++) {
        struct tcp_session *sess = &tcp_sessions[i];
        if (sess->state == SESSION_EMPTY) {
            return i;
        }
    }

    // find free index number failed
    return TCP_SESSIONS_FULL;
}

// fetch tcp session from the tcp sessions array (caller must hold spin lock)
static struct tcp_session *fetch_tcp_session_unlock(struct iphdr *iph, struct tcphdr *tcph) {
    // minimum start index number
    unsigned int min = ntohs(tcph->source)%max_tcp_sessions;
    for (int i = min; i < max_tcp_sessions; i++) {
        struct tcp_session *sess = &tcp_sessions[i];   
        if (sess->state == SESSION_USED) {
            if (sess->daddr == iph->daddr && sess->sport == tcph->source && sess->dport == tcph->dest) {
                return sess;
            }
        }
    }

    return NULL;
}

// fetch buffer from the tcp session  
char *fetch_tcp_buffer(struct iphdr *iph, struct tcphdr *tcph, unsigned int *len) {
    spin_lock(&tcp_lock);
    
    // fetch tcp session
    struct tcp_session *sess = fetch_tcp_session_unlock(iph, tcph);
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

// append tcp data to the tcp buffer
int append_tcp_data(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    // fetch tcp session
    struct tcp_session *sess = fetch_tcp_session_unlock(iph, tcph);
    if (!sess) {
        spin_unlock(&tcp_lock);
        return TCP_SESSION_NOT_FOUND;
    }

    int data_len = ntohs(iph->tot_len)-((iph->ihl*4)+(tcph->doff*4));
    if (data_len <= 0) {
        spin_unlock(&tcp_lock);
        return TCP_INVALID_LENGTH;
    }

    // calculate buffer offset
    int offset = ntohl(tcph->seq)-ntohl(sess->init_seq)-1;
    if (offset < 0) offset = 0;
    
    if (offset+data_len > sess->buffer_len) {
        char *buffer = krealloc(sess->buffer, offset+data_len, GFP_ATOMIC);
        if (!buffer) {
            spin_unlock(&tcp_lock);
            return TCP_REALLOC_ERROR;
        }

        sess->buffer = buffer;
        sess->buffer_len = offset+data_len;
    }

    int data_offset = ((char *)tcph+tcph->doff*4)-(char *)skb->data;
    if (skb_copy_bits(skb, data_offset, sess->buffer+offset, data_len) < 0) {
        spin_unlock(&tcp_lock);
        return TCP_BUFFER_COPY_ERROR;
    } 

    spin_unlock(&tcp_lock);
    return 0;
}

// add a new session to the tcp sessions array
int new_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    int i = find_free_index(tcph->source);
    if (i < 0) {
        spin_unlock(&tcp_lock);
        return i;
    }

    tcp_sessions[i] = (struct tcp_session){
        .daddr = iph->daddr,
        .sport = tcph->source,
        .dport = tcph->dest,
        .init_seq = tcph->seq,
        .buffer = NULL,
        .buffer_len = 0,
        .state = SESSION_USED,
    };

    spin_unlock(&tcp_lock);
    return 0;
}

// remove tcp session to the tcp sessions array
int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    // fetch tcp session
    struct tcp_session *sess = fetch_tcp_session_unlock(iph, tcph);
    if (!sess) {
        spin_unlock(&tcp_lock);
        return TCP_SESSION_NOT_FOUND;
    }

    kfree(sess->buffer);
    memset(sess, 0, sizeof(struct tcp_session));

    spin_unlock(&tcp_lock);
    return 0;
}
