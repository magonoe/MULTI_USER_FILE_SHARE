#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/havege.h"
#include "deriv_passwd.h"

int print_hex(unsigned char *buffer, int buffer_len, char *id)
{
								int i;
								printf(">>> %s\n", id);
								for(i = 0; i < buffer_len; i++)
								{
																printf("%02X", buffer[i]);
								}
								printf("\n");
								return 0;
}

/**
 * @param [out] key           (32 bytes)
 * @param [in]  password      user password
 * @param [in]  salt          salt
 * @param [in]  salt_len      salt length in bytes
 * @param [in]  iterations    number of iterations
 * @return      0 if OK, 1 else
 */
int deriv_passwd(unsigned char *key, char *password, unsigned char *salt, int salt_len,unsigned int iterations) {
								int ret;
								unsigned int i;
								unsigned char hash[32];
								mbedtls_sha256_context ctx;

								/* *** Init *** */
								ret = 1; // error
								i = 0;

								/* *** Check args *** */
								if((key == NULL) || (password == NULL) || (salt == NULL)
											|| (salt_len <= 0) || (iterations == 0))
																goto cleanup;

								/* *** Get H0 *** */
								mbedtls_sha256_starts_ret(&ctx, 0);
								mbedtls_sha256_update_ret(&ctx, (unsigned char *)password, strlen(password));
								mbedtls_sha256_update_ret(&ctx, salt, salt_len);
								mbedtls_sha256_update_ret(&ctx, (unsigned char *)&i, sizeof(int));
								mbedtls_sha256_finish_ret(&ctx, hash); //hash == HO

								/* *** Hi *** */
								for(i = 1; i < iterations; i++) {
																mbedtls_sha256_starts_ret(&ctx, 0);
																mbedtls_sha256_update_ret(&ctx, hash, 32);
																mbedtls_sha256_update_ret(&ctx, (unsigned char *)password,
																																										strlen(password));
																mbedtls_sha256_update_ret(&ctx, salt, salt_len);
																mbedtls_sha256_update_ret(&ctx, (unsigned char *)&i, sizeof(int));
																mbedtls_sha256_finish_ret(&ctx, hash);
								}
								memcpy(key, hash, 32);

								ret = 0;

cleanup:
								memset(&ctx, 0x00, sizeof(mbedtls_sha256_context));
								memset(hash, 0x00, 32);
								return ret;
}
//
//    int gen_key(unsigned char *key, int key_length) {
//         int ret;
//         mbedtls_havege_state ctx;
//
//         ret = 1;
//
//         /* *** check argument *** */
// if((key == NULL) || (key_length <= 0))
//         goto cleanup;
//
//    mbedtls_havege_init(&ctx);
//
//    ret = mbedtls_havege_random(&ctx, key, key_length);
//    cleanup:
//    //memset(&ctx, 0x00, sizeof(mbedtls_havege_state));
//    return ret;
//    }
