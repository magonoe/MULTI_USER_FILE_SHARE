#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "protect_buffer.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/havege.h"
#include "mbedtls/md.h"

#define MBEDTLS_AES_ENCRYPT     1


int gen_key(unsigned char *key, int key_length) {
								int ret;
								mbedtls_havege_state ctx;

								ret = 1;

								/* *** check argument *** */
								if((key == NULL) || (key_length <= 0))
																goto cleanup;

								mbedtls_havege_init(&ctx);

								ret = mbedtls_havege_random(&ctx, key, key_length);
cleanup:
								//memset(&ctx, 0x00, sizeof(mbedtls_havege_state));
								return ret;
}

/**
 * @param [out] output    ciphered buffer
 * @param [out] output_len  ciphered buffer length in bytes
 * @param [in] input     plain text buffer
 * @param [in] input_len			plain text buffer length in bytes
 * @param [in] master_key		master key (km)
 * @param [in] key_len				master key length in bytes
 * @param [in] salt					salt
 * @param [in] salt_len			salt length in bytes
 * @return 0 if OK, 1 else
 */
int protect_buffer(	unsigned char **output, 	int *output_len,
					unsigned char *input, 		int input_len,
					unsigned char *master_key, 	int key_len,
					unsigned char *salt, 		int salt_len)
{
	printf("#######################################\n");
	printf("#####   PROTECT BUFFER FONCTION   #####\n" );

	int ret,j;
	ret = 1;
	/*
	   if((input==NULL)||(input_len <=0)||(master_key==NULL)||(key_len <=0)||(salt==NULL)||(salt_len <=0))
	   {
	   goto cleanup;
	   }*/
	const int SHA256 = 0;
	mbedtls_sha256_context ctx;
	mbedtls_aes_context ctx2;
	mbedtls_md_context_t md_ctx;


	/* * * GENERATION Kc * * */
	/* * * * SHA-256 ( KM||0x00 ) * * * */
	printf("#######################################\n\tKc : " );
	unsigned const char id_Kc=0x00;
	unsigned char *Kc= malloc (sizeof (unsigned char ) * 32);

	mbedtls_sha256_init( &ctx );
	mbedtls_sha256_starts_ret( &ctx, SHA256 );
	mbedtls_sha256_update_ret( &ctx, master_key,key_len );
	mbedtls_sha256_update_ret( &ctx, &id_Kc,(int)1 );
	mbedtls_sha256_finish_ret( &ctx, Kc);
	mbedtls_sha256_free( &ctx );
	for(j = 0; j < 32; j++)
	{
									printf("%02X", Kc[j]);
	}
	printf("\n");


	/* * * GENERATION Ki * * */
	/* * * * SHA-256 ( KM||0x01 ) * * * */
	printf("#######################################\n\tKi : " );
	unsigned const char id_Ki=0x01;
	unsigned char Ki[32];

	mbedtls_sha256_init( &ctx );
	mbedtls_sha256_starts_ret( &ctx, SHA256 );
	mbedtls_sha256_update_ret( &ctx, master_key,key_len );
	mbedtls_sha256_update_ret( &ctx, &id_Ki,(int)1 );
	mbedtls_sha256_finish_ret( &ctx, Ki);
	mbedtls_sha256_free( &ctx );
	for(j = 0; j < 32; j++)
	{
									printf("%02X", Ki[j]);
	}
	printf("\n");

	printf("#######################################\n\tIV : " );
	/* * * * GEN IV  * * * */
	/* * * * gen_key ( 16o ) * * * */
	unsigned char *IV = malloc (sizeof(char) * 16 );
	if (gen_key(IV, 16) != 0)
	{
									goto cleanup;
	}
	for(j = 0; j < 16; j++)
	{
									printf("%02X", IV[j]);
	}
	printf("\n");
	printf("#######################################\n\tTREAT_INPUT");
	printf("\n");
	/* * * TREAT INPUT  * * */
	/* * * * PADING INPUT * * * */
	int pad_len = 16 - (input_len % 16);
	unsigned char *input_padded = (unsigned char *) malloc ( sizeof(unsigned char) * (input_len + pad_len) );
	memcpy(input_padded, input, input_len);
	input_padded[input_len]=0x80;
	int i =1;
	for (; i<pad_len; i++)
	{
									input_padded[input_len+i]=0x00;
	}
	printf("input_padded :\t");
	for (i=0;i<input_len+pad_len;i++)
	{
		printf("%02X",input_padded[i] );
	}
	printf("\n");

	printf("#######################################\n\tMALLOC_OUTPUT");
	unsigned char *outputC = (unsigned char *) malloc ( sizeof(unsigned char) * (input_len + pad_len) );

	printf("\n");
	printf("#######################################\n\tCREATING_BUFFER");
	printf("\n");
	unsigned char *outputF = (unsigned char *) malloc ( sizeof(unsigned char) * (input_len + pad_len + 16 +salt_len+32));

	*output_len = (input_len + pad_len +16 + salt_len+32);
	printf("1 -SALT\t");
	for (j=0; j<salt_len; j++)
	{
									printf("%02X",salt[j]);
									outputF[j] = salt[j];
	}
	printf("\n");
	printf("2 -IV\t");
	for (; j<salt_len+16; j++)
	{
									printf("%02X",IV[j-salt_len]);
									outputF[j]=IV[j-salt_len];
	}
	printf("\n");

	printf("#######################################\n\tCHIFFREMENT_AES");
	/* * * CHIFFREMENT AES  * * */
	/* * * * AES (  INPUT  ) * * * */
	mbedtls_aes_init( &ctx2 );
	mbedtls_aes_setkey_enc( &ctx2, Kc,32*8 );
	mbedtls_aes_crypt_cbc( &ctx2,MBEDTLS_AES_ENCRYPT,input_len+pad_len,IV,input_padded, outputC );
	mbedtls_aes_free( &ctx2 );
	printf("\n");
	printf("#######################################\n\tFEEDING_BUFFER");
	printf("\n3- Buffer : ");
	for (j=salt_len+16; j<salt_len+16+input_len+pad_len; j++)
	{
									printf("%02X", outputC[j-(salt_len+16)]);
									outputF[j]=outputC[j-(salt_len+16)];
	}
	*output = outputF;

	printf("\n");
	printf("#######################################\n\tFINAL_PAYLOAD");
	printf("\n4- payload : ");
	for (j=0; j<salt_len+16+input_len+pad_len; j++)
	{
									printf("%02X", outputF[j]);
	}


	printf("\n");
	printf("#######################################\n\tSIGN");
	printf("\n");

	// printf("BUFFER Kc \n" );
	// int i =0;
	// for (;i<32;i++)
	// {
	//  printf("%02x ",Kc[i] );
	// }
	// printf("\nBUFFER Ki \n" );
	// for (i =0;i<32;i++)
	// {
	//  printf("%02x ",Ki[i] );
	// }
	// AES  ( message )
	// hmac ( Salt+Iv+Cmessage )
	int hmac=1;
	unsigned char *outputS =  (unsigned char *) malloc ( sizeof(unsigned char) * (32));

	//const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string( "MBEDTLS_MD_SHA256" );
	const mbedtls_md_info_t *md_info4 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_init( &md_ctx );

	mbedtls_md_setup( &md_ctx, md_info4, hmac );
	mbedtls_md_hmac_starts( &md_ctx, (const unsigned char *)Ki,(size_t) 32 );
	mbedtls_md_hmac_update( &md_ctx, outputF,(input_len+pad_len+salt_len+16) );
	mbedtls_md_hmac_finish( &md_ctx, outputS );
	printf("5- HMAC :\t");
	for (j=0; j<32; j++)
	{
									printf("%02X",outputS[j]);
									outputF[j+(salt_len+16+input_len+pad_len)]=outputS[j];
	}

	ret = 0;
	printf("\n#######################################\n");
	printf("################    END    ############\n");
	printf("#######################################\n");
cleanup:
	return ret;

}

 /**
  * @param [out] output						plain text buffer
  * @param [out] output_len					plain text buffer length in bytes
  * @param [in] input						ciphered text buffer
  * @param [in] input_len					ciphered text buffer length in bytes
  * @param [in] master_key					master key (km)
  * @param [in] key_len						master key length in bytes
  * @param [in] salt_len					salt length in bytes
  * @return		0 if OK, 1 else
  */
int unprotect_buffer(unsigned char **output, int *output_len,
                      unsigned char *input, int input_len,
                      unsigned char *master_key, int key_len,
                      int salt_len)
{        //SALT//IV//C//SIGN
    printf("#######################################\n");
	printf("##### UNPROTECT BUFFER FONCTION  #####\n" );

	mbedtls_sha256_context ctx;
	mbedtls_aes_context ctx2;
   	mbedtls_md_context_t md_ctx;

    int j,ret=0;
	printf("#######################################\n\tKi : " );
	unsigned const char id_Ki=0x01;
	unsigned char Ki[32];
	const int SHA256 =0;
	mbedtls_sha256_init( &ctx );
	mbedtls_sha256_starts_ret( &ctx, SHA256 );
	mbedtls_sha256_update_ret( &ctx, master_key,key_len );
	mbedtls_sha256_update_ret( &ctx, &id_Ki,(int)1 );
	mbedtls_sha256_finish_ret( &ctx, Ki);
	mbedtls_sha256_free( &ctx );
	for(j = 0; j < 32; j++)
	{
	     printf("%02X", Ki[j]);
	}
	printf("\n");
	printf("#######################################\n\tSIGN VERIFY");
	printf("\n");

	int hmac=1;
	unsigned char *checkSign =  (unsigned char *) malloc ( sizeof(unsigned char) * (32));

	//const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string( "MBEDTLS_MD_SHA256" );
	const mbedtls_md_info_t *md_info4 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_init( &md_ctx );

	mbedtls_md_setup( &md_ctx, md_info4, hmac );
	mbedtls_md_hmac_starts( &md_ctx, (const unsigned char *)Ki,(size_t) 32 );
	mbedtls_md_hmac_update( &md_ctx, input,(input_len-32) );
	mbedtls_md_hmac_finish( &md_ctx, checkSign );
	printf("comparaison:\n");
	printf("input HMAC :\t" );
	for (j=0; j<32; j++)
	{
		printf("%02X",input[j+input_len-32]);
	}
	printf("\n");
	printf("gen HMAC :\t");
	for (j=0; j<32; j++)
	{
		printf("%02X",checkSign[j]);
		if (checkSign[j]!= input[j+input_len-32])
		{
			ret = BAD_SIGN;
			goto cleanup;
		}
	}
	printf("\n");

	printf("#######################################\n\tKc : " );
	unsigned const char id_Kc=0x00;
	unsigned char Kc[32];

	mbedtls_sha256_init( &ctx );
	mbedtls_sha256_starts_ret( &ctx, SHA256 );
	mbedtls_sha256_update_ret( &ctx, master_key,key_len );
	mbedtls_sha256_update_ret( &ctx, &id_Kc,(int)1 );
	mbedtls_sha256_finish_ret( &ctx, Kc);
	mbedtls_sha256_free( &ctx );
	for(j = 0; j < 32; j++)
	{
		printf("%02X", Kc[j]);
	}
	printf("\n");


	printf("#######################################\n\tIV : " );
	unsigned char *IV = malloc (sizeof(char) * 16 );
	for(j = 0; j < 16; j++)
	{
			IV[j]=input[j+salt_len];
			printf("%02X", IV[j]);
	}
	printf("\n");
	printf("#######################################\n\tTREAT_INPUT : " );
	unsigned char *chiffre = malloc (sizeof(char) * (input_len-32-16-salt_len) );
	for(j = 0; j < (input_len-32-16-salt_len); j++)
	{
			chiffre[j]=input[j+salt_len+16];
			printf("%02X", chiffre[j]);
	}

     printf("#######################################\n\tCHIFFREMENT_AES");
     unsigned char *dechiffre = malloc (sizeof(char) * (input_len-32-16-salt_len) );
     mbedtls_aes_init( &ctx2 );
     mbedtls_aes_setkey_dec( &ctx2, Kc,32*8 );
     mbedtls_aes_crypt_cbc( &ctx2,MBEDTLS_AES_DECRYPT,input_len-salt_len-16-32,IV,chiffre, dechiffre );
     mbedtls_aes_free( &ctx2 );
     printf("\n");
     printf("dechiffre :\t" );
    for(j = 0; j < (input_len-32-16-salt_len); j++)
	{
			printf("%02X", dechiffre[j]);
	}
	*output = dechiffre;
	*output_len=(input_len-32-16-salt_len);
    ret = 0;

	printf("\n#######################################\n");
	printf("################    END    ############\n");
	printf("#######################################\n");
cleanup:
     return ret;

}

/**
  * @param [out] output						ciphered text buffer
  * @param [out] output_len					ciphered text buffer length in bytes
  * @param [in] input						plain text buffer
  * @param [in] input_len					plain text buffer length in bytes
  * @param [in] Kc 							cypherKey					
  * @param [in] IV 							Iv
  * @return		0 if OK, 1 else
  */
int chiffre_buffer( unsigned char **output, 	int *output_len,
					unsigned char *input, 		int input_len,
					unsigned char *Kc,
					unsigned char *IV,
					)
{







}






