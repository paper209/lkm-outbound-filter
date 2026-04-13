#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// [\x00\x00\x00\x01][id length (8 bits)][id (n bits)]

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

void deinit_tcp_sessions() {
    for (int i = 0; i < tcp_sessions_len; i++) {
        struct tcp_session *session = tcp_sessions[i];
        
        kfree(session->buffer);
        kfree(session);
    }
    
    kfree(tcp_sessions);
}

int add_tcp_session(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_session *session = kmalloc(sizeof(struct tcp_session), GFP_ATOMIC);
    if (!session) return FALSE;

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

        return FALSE;
    }

    tcp_sessions[tcp_sessions_len-1] = session;

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

int add_data(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_session *session = get_tcp_session(iph, tcph);
    if (!session) return FALSE;

    char *data = (char *)tcph + tcph->doff * 4;
    int data_len = ntohs(iph->tot_len)-((iph->ihl*4)+(tcph->doff*4));
    if (data_len <= 0) return TRUE;

    int offset = ntohl(tcph->seq) - ntohl(session->init_seq);
    if (offset+data_len > session->buffer_len) {
        session->buffer = krealloc(session->buffer, offset+data_len, GFP_ATOMIC);
        if (!session->buffer) return FALSE;

        session->buffer_len = offset+data_len;
    }

    memcpy(session->buffer+offset, data, data_len);

    return TRUE;
}

unsigned int hook_tcp(void *pb, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol == 6) {
        const struct tcphdr *tcph = tcp_hdr(skb);
        if (tcph->syn && !tcph->ack) {
            if (!add_tcp_session(iph, tcph)) {
                printk(KERN_ERR "add tcp session error!!\n");
                return NF_ACCEPT;
            }
        } else {
            if (!add_data(iph, tcph)) {
                printk(KERN_ERR "add data error!!\n");
                return NF_ACCEPT;
            }
        }
    }

    return NF_ACCEPT;
}

const struct nf_hook_ops nfho = {
    .pf = PF_INET,
    .hook = hook_tcp,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

int init(void) {
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "i'm loaded!!!\n");

    return 0;
}

void deinit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    deinit_tcp_sessions();
    
    printk(KERN_INFO "i'm unloaded!\n");
}

module_init(init);
module_exit(deinit);

MODULE_LICENSE("GPL");
