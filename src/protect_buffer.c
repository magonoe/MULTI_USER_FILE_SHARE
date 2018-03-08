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
int protect_buffer( unsigned char **output,  int *output_len,
																				unsigned char *input,   int input_len,
																				unsigned char *master_key,  int key_len,
																				unsigned char *salt,   int salt_len)
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
								for (i=0; i<input_len+pad_len; i++)
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

								printf("#######################################\n\tDECHIFFREMENT_AES");
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
																fprintf(stderr, "Erreur allocation chiffre_buffer\n" );
																ret = 1;
																goto cleanup;
								}
								unsigned char *IV_copy = (unsigned char *) malloc ( sizeof(unsigned char) * 16 );
								memcpy(IV_copy, IV, 16);
								if (mbedtls_aes_setkey_enc( &ctx2, Kc,32*8 ) !=0)
								{
																fprintf(stderr, "MBEDTLS_ERR_AES_INVALID_KEY_LENGTH chiffre_buffer\n");
																ret = 1;
																goto cleanup;
								}
								if ( mbedtls_aes_crypt_cbc( &ctx2,MBEDTLS_AES_ENCRYPT,input_len,IV_copy,input, outputC )!=0)
								{
																fprintf(stderr, "MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH chiffre_buffer\n");
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

int loadInput(unsigned char **output, unsigned int *output_len,const char *filename,int padding)
{
								unsigned char *input=NULL;
								FILE *Fd;
								int input_len=0,pad_len=0;
								Fd = fopen(filename,"r");
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
																if (input_len > 5242880)
																{
																								fprintf(stderr, "Erreur fichier trop grand\n");
																								return 1;
																}
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

int chiffreKc( unsigned char **output,  unsigned int *output_len,
															unsigned char *Kc, const char *filename)
{
								int ret =0;
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

								unsigned char *outputC = (unsigned char*) malloc (sizeof(unsigned char) * 256 );
								size_t olen=0;
								mbedtls_pk_context ctx3;
								mbedtls_pk_init (&ctx3);
								if ((mbedtls_pk_parse_public_keyfile( &ctx3, filename ) )!=0 )
								{
																ret= 1;
																goto cleanup;
								}
								char retr=0;
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

int dechiffreKc(  unsigned char **output,  unsigned int *output_len,
																		unsigned char *input,   unsigned int input_len,
																		const char *filename)
{
								char ret=0;
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
								unsigned char *outputC = (unsigned char*) malloc (sizeof(unsigned char) * 256 );
								size_t olen=0;
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

int findKc( unsigned char *input, unsigned int input_len, unsigned char *key,unsigned char **Kc, unsigned int *offset)
{
								return 1;
}


int signFic(unsigned char **output,  unsigned int *output_len,
												const char *filename, char *key)
{
								int ret = 0;
								mbedtls_pk_context ctx4;
								mbedtls_entropy_context entropy3;
								mbedtls_ctr_drbg_context ctr_drbg;
								unsigned char *outputH= malloc (sizeof (unsigned char ) * 256);
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
								ret = 0;
cleanup:
								mbedtls_pk_free( &ctx4 );
								mbedtls_ctr_drbg_free( &ctr_drbg );
								mbedtls_entropy_free( &entropy3 );
								*output=outputH;
								*output_len=256;
								return ret;
}

int signeKpub(unsigned char **output,  unsigned int *output_len,
														const char *filename)
{
								unsigned char *input=NULL;
								FILE *Fdesc;
								int input_len=0;
								Fdesc = fopen(filename,"rb");
								if (Fdesc==NULL)
								{
																fprintf(stderr, "Erreur ouverture fichier signeKpub\n" );
																return 1;
								}
								else
								{
																fseek(Fdesc, 0, SEEK_END);
																input_len = ftell(Fdesc);
																rewind(Fdesc);
																input = (unsigned char*) malloc(sizeof(unsigned char) * (input_len));
																fread(input, 1, input_len, Fdesc);
																fclose(Fdesc);
																unsigned char *signeKpub= malloc (sizeof (unsigned char ) * 32);
																mbedtls_sha256_context ctx;
																mbedtls_sha256_init( &ctx );

																if ( (mbedtls_sha256_starts_ret( &ctx, 0)) !=0)
																{
																								return 1;
																}
																if ( (mbedtls_sha256_update_ret( &ctx, input,input_len )) !=0)
																{
																								return 1;
																}
																if ( (mbedtls_sha256_finish_ret( &ctx, signeKpub)) !=0)
																{
																								return 1;
																}
																mbedtls_sha256_free( &ctx );
																free(input);
																*output=signeKpub;
																*output_len=32;
																return 0;
								}
								return 1;
}

int verifySign(unsigned char *input, unsigned int input_len,char *key)
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
								int j =0;
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

int checkArg(int argc, char ** argv)
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

int encrypt(int argc, char **argv)
{
								int ret =0;
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

								printf("1 GEN_KC\n");
								if (genKc(&Kc) !=0)
								{
																ret=1;
																goto cleanup;
								}
								printf("2 GEN_IV\n");
								if (genIV(&IV) !=0)
								{
																ret=1;
																goto cleanup;
								}
								printf("3 LOAD_INPUT\n");
								if (loadInput(&input,&input_len,argv[2],1) != 0)
								{
																ret=1;
																goto cleanup;
								}
								printf("4 CHIFFRE_BUFFER\n");
								if (chiffre_buffer(&output,&output_len,input,input_len,Kc,IV) !=0)
								{
																ret=1;
																goto cleanup;
								}
								int nbdestinataire =0;
								char header = 0x00;
								fichierSortie= fopen(argv[3],"a");
								for (; nbdestinataire < (argc - 6); nbdestinataire++)
								{
																printf("5:%d SIGN_KPUB\n",nbdestinataire);
																if (signeKpub(&sha_output, &sha_output_len, argv[nbdestinataire + 6]) != 0)
																{
																								ret=1;
																								goto cleanup;
																}
																printf("6:%d CHIFFRE_KC\n",nbdestinataire);
																if (chiffreKc(&Kc_output, &Kc_output_len, Kc, argv[nbdestinataire + 6]) != 0)
																{
																								ret=1;
																								goto cleanup;
																}
																fwrite(&header,1,1,fichierSortie);
																fwrite(sha_output,1,sha_output_len,fichierSortie);
																fwrite(Kc_output,1,Kc_output_len,fichierSortie);
								}
								header=0x01;
								fwrite(&header,1,1,fichierSortie);
								fwrite(IV,1,16,fichierSortie);
								fwrite(output,1,output_len,fichierSortie);
								fclose(fichierSortie);

								printf("7 SIGN\n");
								if (signFic(&Sign_output,&Sign_output_len,argv[3],argv[4]) != 0)
								{
																ret=1;
																goto cleanup;
								}
								int l=0;
								for (l=0;l<Sign_output_len;l++)
								{
									printf("%02x",Sign_output[l] );
								}
								printf("\nlen %d\n",Sign_output_len);


								fichierSortie= fopen(argv[3],"a");
								if (fichierSortie == NULL)
								{
																ret=1;
																goto cleanup;
								}
								fwrite(Sign_output,1,Sign_output_len,fichierSortie);
								fclose(fichierSortie);
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


int decrypt(int argc, char **argv)
{
								//-d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>

								int ret =0;
								unsigned char *IV=NULL, *Kc=NULL, *input=NULL,*output=NULL,*sha_output=NULL,*Kc_output=NULL,*Sign_output=NULL;
								unsigned int input_len =0,output_len=0,sha_output_len=0,Kc_output_len=0,Sign_output_len=0,offset=0;
								FILE *fichierSortie;
								fichierSortie= fopen(argv[3],"w+");
								if (fichierSortie == NULL)
								{
																ret=1;
																goto cleanup;
								}
								fclose(fichierSortie);

								printf("1 LOAD_INPUT\n");
								if (loadInput(&input,&input_len,argv[2],0) != 0)
								{
																ret=1;
																printf("cocuou\n");
																goto cleanup;
								}
								printf("2 VERIFY_SIGN\n");
								   if (verifySign(input,input_len,argv[6]) !=0)
								   {
								     ret=1;
								     printf("hey\n");
								     goto cleanup;
								   }
								 printf("3 FIND_KC\n");
								   if (findKc(input,input_len,&Kc,&offset,argv[5]) !=0)
								   {
								     ret=1;
								     goto cleanup;
								   }
/*
								   printf("4 DECHIFFRE_BUFFER\n");
								   if (chiffre_buffer(&output,&output_len,input,input_len,Kc,IV) !=0)
								   {
								     ret=1;
								     goto cleanup;
								   }
								   int nbdestinataire =0;
								   char header = 0x00;
								   fichierSortie= fopen(argv[3],"a");
								   for (; nbdestinataire < (argc - 6); nbdestinataire++)
								   {
								     printf("5:%d SIGN_KPUB\n",nbdestinataire);
								     if (signeKpub(&sha_output, &sha_output_len, argv[nbdestinataire + 6]) != 0)
								     {
								             ret=1;
								             goto cleanup;
								     }
								     printf("6:%d CHIFFRE_KC\n",nbdestinataire);
								     if (chiffreKc(&Kc_output, &Kc_output_len, Kc, argv[nbdestinataire + 6]) != 0)
								     {
								             ret=1;
								             goto cleanup;
								     }
								     fwrite(&header,1,1,fichierSortie);
								     fwrite(sha_output,1,sha_output_len,fichierSortie);
								     fwrite(Kc_output,1,Kc_output_len,fichierSortie);
								   }
								   header=0x01;
								   fwrite(&header,1,1,fichierSortie);
								   fwrite(IV,1,16,fichierSortie);
								   fwrite(output,1,output_len,fichierSortie);
								   fclose(fichierSortie);

								   printf("7 SIGN\n");
								   if (signFic(&Sign_output,&Sign_output_len,argv[3],argv[4]) != 0)
								   {
								     ret=1;
								     goto cleanup;
								   }

								   fichierSortie= fopen(argv[3],"a");
								   if (fichierSortie == NULL)
								   {
								     ret=1;
								     goto cleanup;
								   }
								   fwrite(Sign_output,1,Sign_output_len,fichierSortie);
								   fclose(fichierSortie);*/
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





/*
   printf("\tSIGN:\t");
   for (j=0;j<Sign_output_len;j++)
   {
   printf("%02X",Sign_output[j] );
   }
   printf("\n");


   printf("7 DECHIFFRE_KC\n");
   if (dechiffreKc(&Kc_D_output, &Kc_D_output_len, Kc_output, Kc_output_len, argv[7]) != 0)
   {
   return 1;
   }

   printf("\tKc[%d] dechiffre client1:\t",Kc_D_output_len);
   for (j=0;j<Kc_D_output_len;j++)
   {
   printf("%02X",Kc_D_output[j] );
   }
   printf("\n");


   printf("\tKc chiffre client1:\t");
   for (j=0;j<Kc_output_len;j++)
   {
   printf("%02X",Kc_output[j] );
   }
   printf("\n");


   printf("CLAIR :\t");
   for (i=0;i<input_len;i++)
   {
   printf("%02X",input[i] );
   }
   printf("\n");
   printf("CHIFFRE :\t");
   for (i=0;i<output_len;i++)
   {
   printf("%02X",output[i] );
   }
   printf("\n");*/
