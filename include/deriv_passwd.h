#ifndef _DERIV_PASSWD_H
#define _DERIV_PASSWD_H


int print_hex(unsigned char *buffer,
														int buffer_len,
														char *id);

int deriv_passwd(unsigned char *key,
																	char *password,
																	unsigned char *salt,
																	int salt_len,
																	unsigned int iterations);

// int gen_key(unsigned char *key,
// 												int key_length);

#endif
