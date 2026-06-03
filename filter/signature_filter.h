#ifndef SIGNATURE_FILTER_H
#define SIGNATURE_FILTER_H

int init_signature_filter(unsigned int max_len);
void deinit_signature_filter(void);

int new_signature_filter(char *signature, unsigned int siganture_len);
void remove_signature_filter(char *signature, unsigned int signature_len);

bool signature_filter(char *buf, unsigned int len);

#endif
