#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>

#define TRUE 1
#define FALSE 0

struct tcp_session {
    __be32 saddr;
    __be16 sport;
    __be16 dport;

    __be32 init_seq;

    char *buffer;
    int buffer_len;
};


struct tcp_session **tcp_sessions = NULL;
int tcp_sessions_len = 0;

spinlock_t tcp_lock;

void init_tcp_lock(void) {
    spin_lock_init(&tcp_lock);
}

void deinit_tcp_sessions(void) {
    for (int i = 0; i < tcp_sessions_len; i++) {
        struct tcp_session *session = tcp_sessions[i];
        
        kfree(session->buffer);
        kfree(session);
    }
    
    kfree(tcp_sessions);
}

int add_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    struct tcp_session *session = kmalloc(sizeof(struct tcp_session), GFP_ATOMIC);
    if (!session) {
        spin_unlock(&tcp_lock);
        return FALSE;
    }

    session->saddr = iph->saddr;
    session->sport = tcph->source;
    session->dport = tcph->dest;
    session->init_seq = tcph->seq;

    session->buffer = NULL;
    session->buffer_len = 0;

    tcp_sessions = krealloc(tcp_sessions, sizeof(*tcp_sessions)*(++tcp_sessions_len), GFP_ATOMIC);
    if (!tcp_sessions) {
        kfree(session);
        kfree(tcp_sessions);
        
        spin_unlock(&tcp_lock);

        return FALSE;
    }

    tcp_sessions[tcp_sessions_len-1] = session;
    spin_unlock(&tcp_lock);

    return TRUE;
}

struct tcp_session *get_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    for (int i = 0; i < tcp_sessions_len; i++) {
        struct tcp_session *session = tcp_sessions[i];
        if (session->saddr == iph->saddr && session->sport == tcph->source && session->dport == tcph->dest) {
            return session;
        }
    }

    return NULL;
}

int remove_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);

    for (int i = 0; i < tcp_sessions_len; i++) {
        struct tcp_session *session = tcp_sessions[i];
        if (session->saddr == iph->saddr && session->sport == tcph->source && session->dport == tcph->dest) {
            kfree(session->buffer);
            kfree(session);

            for (int j = i; j < tcp_sessions_len - 1; j++) {
                tcp_sessions[j] = tcp_sessions[j + 1];
            }
            tcp_sessions_len--;
            tcp_sessions = krealloc(tcp_sessions, sizeof(*tcp_sessions)*tcp_sessions_len, GFP_ATOMIC);

            spin_unlock(&tcp_lock);

            return FALSE;
        }
    }
    spin_unlock(&tcp_lock);

    return FALSE;
}

int add_tcp_data(struct iphdr *iph, struct tcphdr *tcph) {
    spin_lock(&tcp_lock);
    
    struct tcp_session *session = get_tcp_session(iph, tcph);
    if (!session) {
        spin_unlock(&tcp_lock);
        return FALSE;
    }

    char *data = (char *)tcph + tcph->doff * 4;
    int data_len = ntohs(iph->tot_len)-((iph->ihl*4)+(tcph->doff*4));
    if (data_len <= 0) {
        spin_unlock(&tcp_lock);
        return TRUE;
    }

    int offset = ntohl(tcph->seq) - ntohl(session->init_seq);
    if (offset+data_len > session->buffer_len) {
        session->buffer = krealloc(session->buffer, offset+data_len, GFP_ATOMIC);
        if (!session->buffer) {
            spin_unlock(&tcp_lock);

            return FALSE;
        }

        session->buffer_len = offset+data_len;
    }

    memcpy(session->buffer+offset, data, data_len);
    spin_unlock(&tcp_lock);

    return TRUE;
}
