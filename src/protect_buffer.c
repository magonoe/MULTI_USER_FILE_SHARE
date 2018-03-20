#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>

#include "protect_buffer.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/havege.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


int gen_key(unsigned char *key, int key_length) {
	int ret=0;
	mbedtls_havege_state ctx;
	if((key == NULL) || (key_length <= 0))
	{
		ret = 1;
		goto cleanup;
	}
	mbedtls_havege_init(&ctx);
	ret = mbedtls_havege_random(&ctx, key, key_length);
cleanup:
	mbedtls_havege_free(&ctx);
	return ret;
}

int chiffre_buffer( unsigned char **output,  unsigned int *output_len,
		unsigned char *input,   unsigned int input_len,
		unsigned char *Kc,
		unsigned char *IV
		)
{
	int ret =0;

	mbedtls_aes_context ctx2;
	mbedtls_aes_init( &ctx2 );
	unsigned char *outputC = (unsigned char *) malloc ( sizeof(unsigned char) * (input_len) );
	if (outputC == NULL)
	{
		ret = 1;
		goto cleanup;
	}
	unsigned char *IV_copy = (unsigned char *) malloc ( sizeof(unsigned char) * 16 );
	memcpy(IV_copy, IV, 16);
	if (mbedtls_aes_setkey_enc( &ctx2, Kc,32*8 ) !=0)
	{
		ret = 1;
		goto cleanup;
	}
	if ( mbedtls_aes_crypt_cbc( &ctx2,MBEDTLS_AES_ENCRYPT,input_len,IV_copy,input, outputC )!=0)
	{
		ret = 1;
		goto cleanup;
	}
	free(IV_copy);
	*output = outputC;
	*output_len=input_len;
	ret =0;
cleanup:
	mbedtls_aes_free( &ctx2 );
	return ret;
}

int dechiffre_buffer( unsigned char **output,  unsigned int *output_len,
		unsigned char *input,   unsigned int input_len,
		unsigned char *Kc,
		unsigned char *IV
		)
{
	int ret =0;

	mbedtls_aes_context ctx2;
	mbedtls_aes_init( &ctx2 );
	unsigned char *outputC = (unsigned char *) malloc ( sizeof(unsigned char) * (input_len) );
	if (outputC == NULL)
	{
		ret = 1;
		goto cleanup;
	}
	if (mbedtls_aes_setkey_dec( &ctx2, Kc,32*8 ) !=0)
	{
		ret = 1;
		goto cleanup;
	}
	if ( mbedtls_aes_crypt_cbc( &ctx2,MBEDTLS_AES_DECRYPT,input_len,IV,input, outputC )!=0)
	{
		ret = 1;
		goto cleanup;
	}
	*output = outputC;
	*output_len=input_len;
	ret =0;
cleanup:
	mbedtls_aes_free( &ctx2 );
	return ret;
}

int genKc(unsigned char **Kc)
{
	unsigned char *KC = malloc (sizeof(unsigned char) * 32);
	if (gen_key(KC,32)!=0)
	{
		fprintf(stderr, "Erreur generation Kc\n");
		return 1;
	}
	else
	{
		*Kc=KC;
		return 0;
	}
}

int genIV(unsigned char **IV)
{
	unsigned char *Iv = malloc (sizeof(unsigned char) * 16);
	if (gen_key(Iv,16)!=0)
	{
		fprintf(stderr, "Erreur generation Iv\n");
		return 1;
	}
	else
	{
		*IV=Iv;
		return 0;
	}
}

int loadInput(unsigned char **output, unsigned int *output_len,const char *filename,int *paddinge)
{
	unsigned char *input=NULL;
	FILE *Fd;
	int input_len=0,pad_len=0;
	Fd = fopen(filename,"r");
	int padding = *paddinge;
	if (Fd==NULL)
	{
		fprintf(stderr, "Erreur ouverture fichier\n" );
		return 1;
	}
	else
	{
		fseek(Fd, 0, SEEK_END);
		input_len = ftell(Fd);
		rewind(Fd);
		pad_len= 16 - (input_len % 16);
		input = (unsigned char*) malloc(sizeof(unsigned char) * (input_len+pad_len));
		if (input == NULL)
		{
			fclose(Fd);
			return 1;
		}
		fread(input, 1, input_len, Fd);
		fclose(Fd);
		if (padding ==1)
		{
			input[input_len]=0x80;
			int i;
			for (i=1; i<pad_len; i++)
			{
				input[input_len+i]=0x00;
			}
			*output_len=(input_len+pad_len);
			if (pad_len == 0)
			{
				*paddinge = 0;
			}
		}
		else
		{
			*output_len=(input_len);
		}
		*output=input;
		return 0;
	}
	return 1;
}

int chiffreKc( unsigned char **output, unsigned int *output_len, unsigned char *Kc, const char *filename)
{
	int ret =0;
	char retr=0;
	size_t olen=0;
	unsigned char *outputC = NULL;
	mbedtls_entropy_context entropy1;
	mbedtls_entropy_init( &entropy1 );
	mbedtls_ctr_drbg_context ctr_drbg;
	char *personalization = "Jenaimepasceprojet";
	mbedtls_ctr_drbg_init( &ctr_drbg );
	if ((mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy1, (const unsigned char *) personalization, strlen( personalization ) ))!=0)
	{
		ret= 1;
		goto cleanup;
	}
	outputC= (unsigned char*) malloc (sizeof(unsigned char) * 256 );
	if (outputC == NULL)
	{
		ret= 1;
		goto cleanup;
	}
	mbedtls_pk_context ctx3;
	mbedtls_pk_init (&ctx3);
	if ((mbedtls_pk_parse_public_keyfile( &ctx3, filename ) )!=0 )
	{
		ret= 1;
		goto cleanup;
	}
	if ((retr = mbedtls_pk_encrypt( &ctx3, Kc, 32, outputC, &olen, 256, mbedtls_ctr_drbg_random, &ctr_drbg))!= 0 )
	{
		ret= 1;
		goto cleanup;
	}
	*output=outputC;
	*output_len=olen;
cleanup:
	mbedtls_pk_free( &ctx3 );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy1 );
	return ret;
}

int dechiffreKc( unsigned char **output, unsigned int *output_len, unsigned char *input, unsigned int input_len, const char *filename)
{
	char ret=0;
	unsigned char *outputC=NULL;
	size_t olen=0;
	mbedtls_pk_context ctx3;
	mbedtls_entropy_context entropy2;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init( &entropy2 );
	char *personalization = "Jenaimepasceprojet";
	mbedtls_ctr_drbg_init( &ctr_drbg );
	if ((mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy2, (const unsigned char *) personalization, strlen( personalization ) ))!=0)
	{
		ret= 1;
		goto cleanup;
	}
	outputC= (unsigned char*) malloc (sizeof(unsigned char) * 256 );
	if (outputC == NULL)
	{
		ret= 1;
		goto cleanup;
	}
	mbedtls_pk_init (&ctx3);
	if ((mbedtls_pk_parse_keyfile( &ctx3, filename, "" ) )!=0 )
	{
		ret= 1;
		goto cleanup;
	}
	if ((ret = mbedtls_pk_decrypt( &ctx3, input, input_len, outputC, &olen, 256, mbedtls_ctr_drbg_random, &ctr_drbg))!= 0 )
	{
		ret= 1;
		goto cleanup;
	}
	*output=outputC;
	*output_len=olen;
	ret =0;
cleanup:
	mbedtls_pk_free( &ctx3 );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy2 );
	return ret;
}

int isDest( unsigned char * where, char *key)
{
	unsigned char *output=NULL;
	unsigned int output_len=0;
	signeKpub(&output,&output_len,key);
	return memcmp(output,where,(size_t)output_len);
}

int findKc( unsigned char *input, unsigned int input_len, char *keypub, char *keypriv, unsigned char **Kc, unsigned int *Kc_len, unsigned int *offset)
{
	int cursor = 0;
	int continu = 1;
	int ok =1;
	while(continu == 1)
	{
		if (input[cursor]!=0x00)
		{
			continu = 0;
			*offset=cursor;
		}
		if (continu == 1)
		{
			if (isDest(&(input[cursor+1]),keypub)==0)
			{
				if ( (dechiffreKc(Kc,Kc_len,&(input[cursor+1+32]),256,keypriv))!=0)
				{

					return 1;
				}
				else
				{
					cursor+=289;
					ok=0;
					if (cursor > input_len)
					{
						continu = 0;
					}
				}
			}
			else
			{
				cursor+=289;
				if (cursor > input_len)
				{
					continu = 0;
				}
			}
		}
	}
	return ok;
}

int loadIv( unsigned char **output, unsigned char *input)
{
	int ret = 0;
	unsigned char *outputF = NULL;
	outputF = (unsigned char *) malloc (sizeof(unsigned char) * 16);
	if (outputF == NULL)
	{
		ret =1;
	}
	if ( memcpy(outputF,input,16)== NULL)
	{
		ret = 1;
	}
	*output=outputF;
	return ret;
}

int remove_padding( unsigned int * output_len, unsigned char *input, unsigned int input_len, char pad)
{
	if (pad == 1)
	{
		return 0;
	}
	int j = input_len, continu = 1;
	for (; j >= 0 ; j--)
	{
		if (continu == 1)
		{
			if (input[j] == 0x80)
			{
				continu = 0;
			}
			if (input[j]==0)
			{
				continu = 1;
			}	
		}
		if (continu == 0)
		{
			break;
		}
	}
	*output_len=input_len - j;
	return 0;
}

int signFic( unsigned char **output, unsigned int *output_len, const char *filename, char *key)
{
	int ret = 0;
	unsigned char *outputH=NULL;
	mbedtls_pk_context ctx4;
	mbedtls_entropy_context entropy3;
	mbedtls_ctr_drbg_context ctr_drbg;
	outputH= malloc (sizeof (unsigned char ) * 256);
	if(outputH == NULL)
	{
		ret = 1;
		goto cleanup;
	}
	unsigned char hash[32];
	const char *pers = "silvouplaitfaitequecelacesse";
	size_t olen = 0;
	mbedtls_entropy_init( &entropy3 );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_pk_init( &ctx4 );
	if( ( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy3, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
	{
		ret =1;
		goto cleanup;
	}
	if( (mbedtls_pk_parse_keyfile( &ctx4, key, "" ) ) != 0 )
	{
		ret = 1;
		goto cleanup;
	}
	if( (mbedtls_md_file( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), filename, hash ) ) != 0 )
	{
		ret =1;
		goto cleanup;
	}
	if( (mbedtls_pk_sign( &ctx4, MBEDTLS_MD_SHA256, hash, 0, outputH, &olen, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
	{
		ret =1;
		goto cleanup;
	}
	*output=outputH;
	*output_len=256;
	ret = 0;
cleanup:
	mbedtls_pk_free( &ctx4 );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy3 );
	return ret;
}

int signeKpub( unsigned char **output, unsigned int *output_len, const char *filename)
{
	int ret=0;
	unsigned char *input=NULL,*signeKpub=NULL;
	FILE *Fdesc;
	int input_len=0;
	Fdesc = fopen(filename,"rb");
	if (Fdesc==NULL)
	{
		ret =1;
		goto cleanup;
	}
	fseek(Fdesc, 0, SEEK_END);
	input_len = ftell(Fdesc);
	rewind(Fdesc);
	input = (unsigned char*) malloc(sizeof(unsigned char) * (input_len));
	if (input == NULL)
	{
		ret =1;
		goto cleanup;
	}
	fread(input, 1, input_len, Fdesc);
	fclose(Fdesc);
	signeKpub= malloc (sizeof (unsigned char ) * 32);
	if (signeKpub == NULL)
	{
		ret =1;
		goto cleanup;
	}
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init( &ctx );
	if ( (mbedtls_sha256_starts_ret( &ctx, 0)) !=0)
	{
		ret =1;
		goto cleanup;
	}
	if ( (mbedtls_sha256_update_ret( &ctx, input,input_len )) !=0)
	{
		ret =1;
		goto cleanup;
	}
	if ( (mbedtls_sha256_finish_ret( &ctx, signeKpub)) !=0)
	{
		ret =1;
		goto cleanup;
	}
	*output=signeKpub;
	*output_len=32;
	ret = 0;
cleanup:
	mbedtls_sha256_free( &ctx );
	if (input !=NULL)
	{
		free(input);
	}
	return ret;
}

int verifySign( unsigned char *input, unsigned int input_len, char *key)
{
	int ret = 0;
	char val=0;
	mbedtls_pk_context ctx5;
	mbedtls_sha256_context ctx6;
	const int SHA256 = 0;
	unsigned char *hash= malloc (sizeof (unsigned char ) * 32);
	mbedtls_pk_init( &ctx5 );
	if( (mbedtls_pk_parse_public_keyfile( &ctx5, key) ) != 0 )
	{
		ret = 1;
		goto cleanup;
	}
	mbedtls_sha256_init( &ctx6 );
	mbedtls_sha256_starts_ret( &ctx6, SHA256 );
	mbedtls_sha256_update_ret( &ctx6, input,input_len-256 );
	mbedtls_sha256_finish_ret( &ctx6, hash);
	if( (val = mbedtls_pk_verify( &ctx5, MBEDTLS_MD_SHA256, hash, 0,&input[input_len-256], 256 ) ) !=0)
	{
		ret =1;
		goto cleanup;
	}
	ret = 0;
cleanup:
	mbedtls_pk_free( &ctx5 );
	mbedtls_sha256_free( &ctx6 );
	if (hash !=NULL)
	{
		free(hash);
	}
	return ret;
}

int checkArg( int argc, char ** argv)
{
	if (argc<=6)
	{
		return 0;
	}
	if (strcmp(argv[1],"-e")==0)
	{
		if (access(argv[2], R_OK) == -1)
		{
			return 3;
		}
		if (access(argv[4], R_OK) == -1)
		{
			return 4;
		}
		if (access(argv[5], R_OK) == -1)
		{
			return 5;
		}
		int i;
		for (i=6; i<argc; i++)
		{
			if (access(argv[i], R_OK) == -1)
			{
				return 6;
			}
		}
		return 1;
	}
	else if (strcmp(argv[1],"-d")==0)
	{
		if (argc !=7 )
		{
			return 7;
		}
		if (access(argv[2], R_OK) == -1)
		{
			return 8;
		}
		if (access(argv[4], R_OK) == -1)
		{
			return 9;
		}
		if (access(argv[5], R_OK) == -1)
		{
			return 10;
		}
		if (access(argv[6], R_OK) == -1)
		{
			return 11;
		}
		return 2;
	}
	else
	{
		return 12;
	}
}

int encrypt( int argc, char **argv)
{
	int ret =0,pad=1;
	unsigned char *IV=NULL, *Kc=NULL, *input=NULL,*output=NULL,*sha_output=NULL,*Kc_output=NULL,*Sign_output=NULL;
	unsigned int input_len =0,output_len=0,sha_output_len=0,Kc_output_len=0,Sign_output_len=0;
	FILE *fichierSortie;
	fichierSortie= fopen(argv[3],"w+");
	if (fichierSortie == NULL)
	{
		ret=1;
		goto cleanup;
	}
	fclose(fichierSortie);

	printf("1 GEN_KC\t\t\t");
	if (genKc(&Kc) !=0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("2 GEN_IV\t\t\t");
	if (genIV(&IV) !=0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("3 LOAD_INPUT\t\t\t");
	if (loadInput(&input,&input_len,argv[2],&pad) != 0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("4 CHIFFRE_BUFFER\t\t");
	if (chiffre_buffer(&output,&output_len,input,input_len,Kc,IV) !=0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	int nbdestinataire =0;
	char header = 0x00;
	fichierSortie= fopen(argv[3],"a");
	for (; nbdestinataire < (argc - 6); nbdestinataire++)
	{
		printf("5:%d SIGN_KPUB\t\t\t",nbdestinataire);
		if (signeKpub(&sha_output, &sha_output_len, argv[nbdestinataire + 6]) != 0)
		{
			ret=1;
			goto cleanup;
		}
		printf("OK\n");
		printf("6:%d CHIFFRE_KC\t\t\t",nbdestinataire);
		if (chiffreKc(&Kc_output, &Kc_output_len, Kc, argv[nbdestinataire + 6]) != 0)
		{
			ret=1;
			goto cleanup;
		}
		printf("OK\n");
		printf("7:%d WRITING_SHA_KC_TO_FILE\t",nbdestinataire);
		fwrite(&header,1,1,fichierSortie);
		fwrite(sha_output,1,sha_output_len,fichierSortie);
		fwrite(Kc_output,1,Kc_output_len,fichierSortie);
		printf("OK\n");
	}
	printf("8 WRITING_DATA_TO_FILE\t\t");
	header=0x01+(char)pad;
	fwrite(&header,1,1,fichierSortie);
	fwrite(IV,1,16,fichierSortie);
	fwrite(output,1,output_len,fichierSortie);
	fclose(fichierSortie);
	printf("OK\n");
	printf("9 SIGN\t\t\t\t");
	if (signFic(&Sign_output,&Sign_output_len,argv[3],argv[4]) != 0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("10 WRITING_SIGN_TO_FILE\t\t");
	fichierSortie= fopen(argv[3],"a");
	if (fichierSortie == NULL)
	{
		ret=1;
		goto cleanup;
	}
	fwrite(Sign_output,1,Sign_output_len,fichierSortie);
	fclose(fichierSortie);
	printf("OK\n");
	ret =0;
cleanup:
	if(Kc!=NULL)
	{
		memset(Kc,0,32);
		free(Kc);
	}

	if (IV!=NULL)
	{
		memset(IV,0,16);
		free(IV);
	}

	if (input!=NULL)
	{
		memset(input,0,input_len);
		free(input);
	}

	if (output!=NULL)
	{
		memset(output,0,output_len);
		free(output);
	}

	if (sha_output!=NULL)
	{
		memset(sha_output,0,sha_output_len);
		free(sha_output);
	}

	if (Kc_output!=NULL)
	{
		memset(Kc_output,0,Kc_output_len);
		free(Kc_output);
	}

	if (Sign_output!=NULL)
	{
		memset(Sign_output,0,Sign_output_len);
		free(Sign_output);
	}
	return ret;
}

int decrypt( int argc, char **argv)
{
	int ret =0,pad=0;
	unsigned char *Kc=NULL, *input=NULL,*IV=NULL,*output=NULL;
	unsigned int input_len =0,Kc_len=0,offset=0,output_len=0,outputF_len=0;
	FILE *fichierSortie;
	fichierSortie= fopen(argv[3],"w+");
	if (fichierSortie == NULL)
	{
		ret=1;
		goto cleanup;
	}
	fclose(fichierSortie);

	printf("1 LOAD_INPUT\t\t\t");
	if (loadInput(&input,&input_len,argv[2],&pad) != 0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("2 VERIFY_SIGN\t\t\t");
	if (verifySign(input,input_len,argv[6]) !=0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("3 FIND_KC\t\t\t");
	if (findKc(input,input_len,argv[5],argv[4],&Kc,&Kc_len,&offset) !=0)
	{
		printf("No Kc found !\n");
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("4 LOAD_IV\t\t\t");
	if (loadIv(&IV,&(input[offset+1]))!=0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("5 DECHIFFRE_BUFFER\t\t");
	if (dechiffre_buffer(&output,&output_len,&(input[offset+1+16]),(input_len-offset-256-16-1),Kc,IV) !=0)
	{
		ret=1;
		goto cleanup;
	}
	printf("OK\n");
	printf("6 REMOVE_PADDING\t\t");
	if (remove_padding(&outputF_len,output,output_len ,input[offset]) !=0)
	{
		ret = 1;
		goto cleanup;
	}
	printf("OK\n");
	printf("7 WRITING_TO_FILE\t\t");
	fichierSortie= fopen(argv[3],"a");
	if (fichierSortie == NULL)
	{
		ret=1;
		goto cleanup;
	}
	fwrite(output,1,(output_len-outputF_len),fichierSortie);
	fclose(fichierSortie);
	printf("OK\n");
	ret =0;
cleanup:
	if(Kc!=NULL)
	{
		memset(Kc,0,32);
		free(Kc);
	}

	if (IV!=NULL)
	{
		memset(IV,0,16);
		free(IV);
	}

	if (input!=NULL)
	{
		memset(input,0,input_len);
		free(input);
	}

	if (output!=NULL)
	{
		memset(output,0,output_len);
		free(output);
	}
	return ret;
}

void help()
{
	printf("Usage : multi_protect <MODE> <input_file> <output_file> <ARGV_KEY>\n");
	printf("\n");
	printf("<MODE>\n");
	printf("\t-e\t cipher mode\n");
	printf("\t\t\t <ARGV_KEY>:  <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]\n");
	printf("\n");
	printf("\t-d\t uncipher mode\n");
	printf("\t\t\t <ARGV_KEY>:  <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>\n");
	return;
}
