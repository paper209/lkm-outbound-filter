#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#include "../filter/filter.h"
#include "../filter/port_filter.h"
#include "../filter/netmask_filter.h"
#include "../filter/signature_filter.h"

#include "parser.h"

static void parse_port_filter(const char *buf, const size_t len) {
    if (len < 4) return;
    __u8 protocol = 0;
    memcpy(&protocol, buf+1, sizeof(protocol));

    __be16 port = 0;
    memcpy(&port, buf+2, sizeof(port));

    if (buf[0] == SET_PORT_FILTER) {
        if (new_port_filter(port, protocol) == FILTER_IS_FULL) {
            printk(KERN_ERR "set port filter error: filter is full\n");
        }
    } else if (buf[0] == REMOVE_PORT_FILTER) {
        remove_port_filter(port, protocol);
    }
}

static void parse_netmask_filter(const char *buf, const size_t len) {
    if (len < 9) return;
    __be32 address, mask;
    memcpy(&address, buf+1, sizeof(address));
    memcpy(&mask, buf+5, sizeof(mask));

    if (buf[0] == SET_NETMASK_FILTER) {
        if (new_netmask_filter(address, mask) == FILTER_IS_FULL) {
            printk(KERN_ERR "set netmask filter error: filter is full\n");
        }
    } else if (buf[0] == REMOVE_NETMASK_FILTER) {
        remove_netmask_filter(address, mask);
    }
}

static void pasre_signature_filter(const char *buf, const size_t len) {
    if (len < 2) return;
    char *signature = buf+1;
    size_t signature_len = len-1;

    if (buf[0] == SET_SIGNATURE_FILTER) {
        if (new_signature_filter(signature, signature_len) == FILTER_IS_FULL) {
            printk(KERN_ERR "set signature filter error: filter is full\n");
        }
    } else if (buf[0] == REMOVE_SIGNATURE_FILTER) {
        remove_signature_filter(signature, signature_len);
    }
}

void parse_set_packet(struct sk_buff *skb, const struct udphdr *udph) {
    size_t len = ntohs(udph->len)-sizeof(struct udphdr);
    if (len < 1) return;

    char *buffer = kmalloc(len, GFP_ATOMIC);
    if (!buffer) return;

    int offset = (char *)(udph+1)-(char *)skb->data;
    if (skb_copy_bits(skb, offset, buffer, len) < 0) {
        kfree(buffer);
        return;
    }

    switch (buffer[0]) {
        case REMOVE_PORT_FILTER:
        case SET_PORT_FILTER: {
            parse_port_filter(buffer, len);
            break;
        }

        case REMOVE_NETMASK_FILTER:
        case SET_NETMASK_FILTER: {
            parse_netmask_filter(buffer, len);
            break;
        }

        case REMOVE_SIGNATURE_FILTER:
        case SET_SIGNATURE_FILTER: {
            pasre_signature_filter(buffer, len);
            break;
        }
    }

    kfree(buffer); 
}
