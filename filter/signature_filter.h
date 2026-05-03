#ifndef SIGNATURE_FILTER_H
#define SIGNATURE_FILTER_H

void init_signature_lock(void);
void deinit_signature_filter(void);
int add_signature_filter(char *signature, unsigned int signature_len);
int remove_signature_filter(char *signature, unsigned int signature_len);
bool signature_filter(struct iphdr *iph, struct sk_buff *skb);

#endif
