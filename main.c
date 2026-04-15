#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "tcp/tcp.h"

// [\x00\x00\x00\x01][id length (8 bits)][id (n bits)]
unsigned int hook(void *pb, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *iph = ip_hdr(skb);
    switch (iph->protocol) {
        case 6: {
            const struct tcphdr *tcph = tcp_hdr(skb);
            if (tcph->syn && !tcph->ack) {
                switch (add_tcp_session(iph, tcph)) {
                    case TCP_ALLOC_ERROR:
                        printk(KERN_ERR "new tcp connection: alloc error.\n");
                        break;
                    case TCP_REALLOC_ERROR:
                        printk(KERN_ERR "new tcp connection: realloc error.\n");
                        break;
                }
            } else if (tcph->fin) {
                remove_tcp_session(iph, tcph)
            } else {
                switch (add_tcp_data(skb, iph, tcph)) {
                    case TCP_REALLOC_ERROR:
                        printk(KERN_ERR "tcp added: realloc error.\n");
                        break;
                    case TCP_BUFFER_COPY_ERROR:
                        printk(KERN_ERR "tcp added: buffer copy error.\n");
                        break;
                }
            }

            break;
        }
    }

    return NF_ACCEPT;
}

const struct nf_hook_ops nfho = {
    .pf = PF_INET,
    .hook = hook,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

int init(void) {
    init_tcp_lock();
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
