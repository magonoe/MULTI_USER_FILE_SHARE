#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protect_buffer.h"
#include "deriv_passwd.h"
int get_masterKey();

int main (int argc, char ** argv){

	unsigned char key[32];
	char *password;
	unsigned char *salt;

	unsigned char clair_init[50]="Salut a tous, bienvenue dans ce monde merveilleux";
	unsigned char *chiffre=NULL,*dechiffre;
	int chiffre_len=0,dechiffre_len=0,salt_len = strlen(argv[2]);

/* *** check parameters *** */
	if (argc != 4) {
									fprintf(stderr, "usage : %s <password> <salt> <iterations>\n", argv[0]);
									return 1;
	}
	else if (strlen(argv[1]) > 32) {
									fprintf(stderr, "error : password too long (32 characters max)\n");
									return 1;
	}
	else if (strlen(argv[2]) > 16) {
									fprintf(stderr, "error : salt too long (16 charachers max)\n");
									return 1;
	}
	else if (!atoi(argv[3]) || atoi(argv[3]) < 1) {
									fprintf(stderr, "error : number of iterations must be a positive integer\n");
									return 1;
	}

/* *** initialization *** */
	password = NULL;
	salt = NULL;


	int a,i;
	a = get_masterKey(password, &salt, key, argv);
	printf("result get_masterKey : %d\n\n\n",a );


	a = protect_buffer(&chiffre, &chiffre_len, clair_init,50,key, (int) 32, salt,salt_len );
	printf("result protect_buffer : %d\n\n\n",a );

	a= unprotect_buffer(&dechiffre, &dechiffre_len, chiffre, chiffre_len, key, (int) 32,salt_len);
	printf("result unprotect_buffer : %d\n\n\n",a );









printf("message clair : %s\n",clair_init );


	printf("CLAIR : \t" );
	for (i=0; i<50; i++)
	{
									printf("%02X",clair_init[i] );
	}
	printf("\n");
	printf("CHIFFRE : \t" );
	for (i=0; i<chiffre_len; i++)
	{
									printf("%02X",chiffre[i] );
	}
	printf("\n");
	printf("DECHIFFRE : \t" );
	for (i=0; i<dechiffre_len; i++)
	{
									printf("%02X",dechiffre[i] );
	}
	printf("\n");
	printf("message dechiffre : %s\n",dechiffre );


// protect_buffer(NULL, 0,NULL , 0, *master_key, int key_len,
								//  unsigned char *salt, int salt_len)


//  if(argc != 2){
//   printf("Usage : ./gen_key KEY_LENGTH\n");
//   return -1;
//  }
//
//  int ret;
//  int key_length = atoi(argv[1]);
//
//  if(key_length <= 0){
//   printf("/!\\ KEY_LENGTH < ou = 0\n");
//   return -1;
//  }
//
//  unsigned char *key = (unsigned char *)malloc(key_length *sizeof(char));
//
//  if (key == NULL){
//  }
//
//  ret = gen_key(key, key_length);
//
//  if(ret!=0)
//   goto cleanup;
//
//  print_hex(key, key_length, "key = ");
//
//  ret = 0;
//
// cleanup:
//  memset(key, 0x00, key_length);
//  free(key);
//  key = NULL;
//

								return 0;
}

int get_masterKey(char * password, unsigned char **salt, unsigned char key[],char ** argv)
{
								int ret, password_len, salt_len;
								unsigned int iterations;
								/* *** get password *** */
								password_len = strlen(argv[1]);
								password = (char *) malloc(sizeof(char) * (password_len + 1));
								if (password ==  NULL) {
																fprintf(stderr, "error : memory allocation failed\n");
																ret = 1;
																goto cleanup;
								}
								strcpy(password, argv[1]);
								password[password_len] = '\0';

								/* *** get salt *** */
								salt_len = strlen(argv[2]);
								*salt = (unsigned char *) malloc(sizeof(unsigned char) * salt_len);
								if (salt == NULL) {
																fprintf(stderr, "error : memory allocation failed\n");
																ret = 1;
																goto cleanup;
								}
								memcpy(*salt, argv[2], salt_len);
								/* *** get number of iterations *** */
								iterations = atoi(argv[3]);

								/* *** deriv password *** */
								ret =  deriv_passwd(key, password, *salt, salt_len, iterations);
cleanup:
								return ret;

}
