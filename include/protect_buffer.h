#ifndef _PROTECT_BUFFER_H
#define _PROTECT_BUFFER_H

int gen_key	(		unsigned char *key,			int key_length
					);

int genKc(			unsigned char **Kc
					);

int genIV(			unsigned char **IV
					);

int loadInput(		unsigned char **output, 	unsigned int *output_len,
					const char *filename, 		int *paddinge
					);

int chiffre_buffer( unsigned char **output, 	unsigned int *output_len,
					unsigned char *input, 		unsigned int input_len,
					unsigned char *Kc,
					unsigned char *IV
					);

int dechiffre_buffer( unsigned char **output, 	unsigned int *output_len,
					unsigned char *input, 		unsigned int input_len,
					unsigned char *Kc,
					unsigned char *IV
					);

int isDest(			unsigned char * where,		char *key
					);

int chiffreKc( 		unsigned char **output, 	unsigned int *output_len,
					unsigned char *Kc , 		const char *filename
					);

int dechiffreKc( 	unsigned char **output, 	unsigned int *output_len,
					unsigned char *input, 		unsigned int input_len,
					const char *filename
					);

int findKc( 		unsigned char *input, 		unsigned int input_len, 
					char *keypub,				char *keypriv,
					unsigned char **Kc,			unsigned int *Kc_len, 
					unsigned int *offset
					);

int signFic(		unsigned char **output, 	unsigned int *output_len,
					const char *filename, 		char *key
					);

int remove_padding(	unsigned int * output_len,
					unsigned char *input, 		unsigned int input_len ,
					char pad
					);

int loadIv(			unsigned char **output, 	unsigned char *input
					);

int signeKpub( 		unsigned char **output, 	unsigned int *output_len,
					const char *filename
					);

int verifySign(		unsigned char *input, 		unsigned int input_len,
					char *key
					);

int checkArg(		int argc, 					char ** argv
					);

int encrypt(		int argc,	 				char **argv
					);

int decrypt(		int argc, 					char **argv
					);

void help();

#endif