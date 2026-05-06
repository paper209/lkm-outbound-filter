#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/spinlock.h>

#include "filter.h"
#include "../tcp/tcp.h"

// signature filter
struct filter {
    char *signature;
    unsigned int signature_len;

    enum filter_state state;
};

static spinlock_t signature_lock;

static struct filter *filters = NULL; // signature filters array
static unsigned int max_filters_len = 0; // signature filters array's max length

// init signature filter's spinlock
static void init_signature_lock(void) {
    spin_lock_init(&signature_lock);
}

// init signature filters array and spinlock
int init_signature_filter(unsigned int max_len) {
    init_signature_lock();
    spin_lock(&signature_lock);

    max_filters_len = max_len;
    filters = kcalloc(max_filters_len, sizeof(struct filter), GFP_ATOMIC);
    if (!filters) {
        spin_unlock(&signature_lock);
        return FILTER_ALLOC_ERROR;
    }

    spin_unlock(&signature_lock);
    return 0;
}

// deinit signature filters array and signature array
void deinit_signature_filter(void) {
    spin_lock(&signature_lock);
    for (int i = 0; i < max_filters_len; i++) {
        struct filter *f = &filters[i];
        kfree(f->signature);
    }
    kfree(filters);
    spin_unlock(&signature_lock);
}

// find free index on netmask filters array
static int find_free_index(char *signature) {
    // calculate minimum start index number
    unsigned int min = signature[0]%max_filters_len;
    
    // find free index number and return
    for (int i = min; i < max_filters_len; i++) {
        struct filter *f = &filters[i];
        if (f->state == FILTER_EMPTY) {
            return i;
        }
    }

    // find free index number failed
    return FILTER_IS_FULL;
}

// add a new signature filter
int new_signature_filter(char *signature, unsigned int signature_len) {
    spin_lock(&signature_lock);
    
    // find free index using signature len
    int i = find_free_index(signature);
    if (i < 0) {
        spin_unlock(&signature_lock);
        return i;
    }

    // copy a signature buffer
    char *copy_signature = kmalloc(signature_len, GFP_ATOMIC);
    if (!copy_signature) {
        spin_unlock(&signature_lock);
        return FILTER_ALLOC_ERROR;
    }
    memcpy(copy_signature, signature, signature_len);

    // add signature filter
    filters[i] = (struct filter){
        .signature = copy_signature,
        .signature_len = signature_len,
        .state = FILTER_USED,
    };

    // debug
    printk(KERN_INFO "added signature filter: %u\n", signature_len);

    spin_unlock(&signature_lock);
    return 0;
}

// remove signature filter
void remove_signature_filter(char *signature, unsigned int signature_len) {
    spin_lock(&signature_lock);

    // calculate minimum start index number
    unsigned int min = signature[0]%max_filters_len;
    for (int i = min; i < max_filters_len; i ++) {
        struct filter *f = &filters[i];
        if (f->state == FILTER_USED) {
            if (f->signature_len == signature_len && memcmp(signature, f->signature, f->signature_len) == 0) {
                kfree(f->signature);
                memset(f, 0, sizeof(struct filter));
                break;
            }
        }
    }

    // debug
    printk(KERN_INFO "removed signature filter: %u\n", signature_len);
    
    spin_unlock(&signature_lock);
}


// check the signature filters
static bool check_signature(const char *buf, int buf_len) {
    spin_lock(&signature_lock);

    // calculate minimum start index number
    unsigned int min = buf[0]%max_filters_len;
    for (int i = min; i < max_filters_len; i++) {
        struct filter *f = &filters[i];
        if (f->signature_len > buf_len) continue;

        // check the signature
        for (int j = 1; j <= buf_len-f->signature_len; j++) {
            if (f->state == FILTER_USED) {
                if (memcmp(buf+j, f->signature, f->signature_len) == 0) {
                    spin_unlock(&signature_lock);
                    return true;
                }
            }
        }
    }

    spin_unlock(&signature_lock);
    return false;
}

// check the signature filters and compare the buffer
bool signature_filter(struct iphdr *iph, struct sk_buff *skb) {
    switch (iph->protocol) {
        // tcp
        case 6: {
            const struct tcphdr *tcph = tcp_hdr(skb);
            
            unsigned int buffer_len;
            char *buf = fetch_tcp_buffer(iph, tcph, &buffer_len);
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
