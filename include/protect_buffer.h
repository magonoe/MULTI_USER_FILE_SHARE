#ifndef _PROTECT_BUFFER_H
#define _PROTECT_BUFFER_H

int gen_key(unsigned char *key,
												int key_length);
int protect_buffer(unsigned char **output, int *output_len,
																			unsigned char *input, int input_len,
																			unsigned char *master_key, int key_len,
																			unsigned char *salt, int salt_len);


int unprotect_buffer(unsigned char **output, int *output_len,
                      unsigned char *input, int input_len,
                      unsigned char *master_key, int key_len,
                      int salt_len);


#define BAD_SIGN 0x500




#endif
