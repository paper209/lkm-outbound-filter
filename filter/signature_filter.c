#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "filter.h"
#include "../tcp/tcp.h"

struct filter {
    char *signature;
    unsigned int signature_len;
};

struct filter *signature_filters = NULL;
unsigned int signature_filters_len = 0;

void deinit_signature_filter(void) {
    spin_lock(&filter_lock);
    for (int i = 0; i < signature_filters_len; i++) {
        struct filter *f = &signature_filters[i];
        kfree(f->signature);
    }

    kfree(signature_filters);
    spin_unlock(&filter_lock);
}

int add_signature_filter(char *signature, unsigned int signature_len) {
    spin_lock(&filter_lock);

    struct filter *filters = krealloc(signature_filters, sizeof(struct filter)*++signature_filters_len, GFP_ATOMIC);
    if (!filters) {
        signature_filters_len--;
        spin_unlock(&filter_lock);

        return FILTER_REALLOC_ERROR;
    }
    signature_filters = filters;

    char *copy_signature = kmalloc(signature_len, GFP_ATOMIC);
    if (!copy_signature) {
        signature_filters_len--;
        spin_unlock(&filter_lock);
        return FILTER_ALLOC_ERROR;
    }
    memcpy(copy_signature, signature, signature_len);

    signature_filters[signature_filters_len-1] = (struct filter){
        .signature = copy_signature,
        .signature_len = signature_len,
    };

    printk(KERN_INFO "added signature filter: %u\n", signature_len);
    
    spin_unlock(&filter_lock);
    
    return 0;
}

int remove_signature_filter(char *signature, unsigned int signature_len) {
    spin_lock(&filter_lock);

    for (int i = 0; i < signature_filters_len; i++) {
        struct filter *f = &signature_filters[i];
        if (f->signature_len == signature_len && memcmp(signature, f->signature, f->signature_len) == 0) {
            kfree(f->signature);
            signature_filters_len--;

            for (int j = i; j < signature_filters_len; j++) {
                signature_filters[j] = signature_filters[j+1];
            }

            struct filter *filters = krealloc(signature_filters, sizeof(struct filter)*signature_filters_len, GFP_ATOMIC);
            if (!filters) {
                spin_unlock(&filter_lock);

                return FILTER_REALLOC_ERROR;
            }
            signature_filters = filters;

            break;
        }
    }
    printk(KERN_INFO "removed signature filter: %u\n", signature_len);
    
    spin_unlock(&filter_lock);
    return 0;
}

bool check_signature(const char *buf, int buf_len) {
    for (int i = 0; i < signature_filters_len; i++) {
        struct filter *f = &signature_filters[i];
        if (f->signature_len > buf_len) continue;

        for (int j = 0; j <= buf_len-f->signature_len; j++) {
            if (buf[j] == f->signature[0]) {
                if (memcmp(buf+j, f->signature, f->signature_len) == 0) {
                    //kfree(buf);
                    return true;
                }
            }
        }
    }

    //kfree(buf);
    return false;
}

bool signature_filter(struct iphdr *iph, struct sk_buff *skb) {
    switch (iph->protocol) {
        // tcp
        case 6: {
            const struct tcphdr *tcph = tcp_hdr(skb);
            
            unsigned int buffer_len;
            char *buf = get_tcp_buffer(iph, tcph, buffer_len);
            if (!buf) return false;

            bool ret = check_signature(buf, buffer_len);
            kfree(buf);

            return ret;
        }

        // udp
        case 17: {
            const struct udphdr *udph = udp_hdr(skb);
            int buffer_len = ntohs(udph->len)-sizeof(struct udphdr);
            if (buffer_len < 0) return false;

            char *buf = kmalloc(buffer_len, GFP_ATOMIC);
            if (!buf) return false;

            int data_offset = (char *)(udph+1)-(char *)skb->data;
            if (skb_copy_bits(skb, data_offset, buf, buffer_len) < 0) {
                kfree(buf);
                return false;
            }

            bool ret = check_signature(buf, buffer_len);
            kfree(buf);

            return ret;
        }
    }

    return false;
}
