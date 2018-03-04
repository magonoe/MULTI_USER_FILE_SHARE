#ifndef _PROTECT_BUFFER_H
#define _PROTECT_BUFFER_H

int gen_key	(unsigned char *key,		int key_length);

int genKc(unsigned char **Kc);
int genIV(unsigned char **IV);
int loadInput(unsigned char **output, 	unsigned int *output_len,
				const char *filename);

int chiffre_buffer( unsigned char **output, 	unsigned int *output_len,
					unsigned char *input, 		unsigned int input_len,
					unsigned char *Kc,
					unsigned char *IV
					);

int chiffreKc( 	unsigned char **output, 	unsigned int *output_len,
				unsigned char *Kc , const char *filename);

int dechiffreKc( 	unsigned char **output, 	unsigned int *output_len,
					unsigned char *input, 		unsigned int input_len,
					const char *filename);

int signeKpub( 	unsigned char **output, 	unsigned int *output_len,
				const char *filename);


int checkArg(int argc, char ** argv);
int encrypt(int argc, char **argv);

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
