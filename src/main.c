#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protect_buffer.h"
#include "deriv_passwd.h"
int get_masterKey();

int main (int argc, char ** argv){
	unsigned char *Kc = malloc (sizeof(unsigned char) * 32);
	unsigned char *IV = malloc (sizeof(unsigned char) * 16);
	if (gen_key(Kc,32)!=0)
	{
		fprintf(stderr, "Erreur generation Kc\n");
		return 1;
	}

	if (gen_key(IV, 16) != 0)
	{
		fprintf(stderr, "Erreur generation IV\n");
		return 1;
	}

	unsigned char *input=NULL;

	FILE *Fd;
	int input_len=0;
	Fd = fopen(argv[1],"r");
	if (Fd!=NULL)
	{
		fseek(Fd, 0, SEEK_END);
        input_len = ftell(Fd);
        rewind(Fd);
        if (input_len > 5242880)
        {
        	fprintf(stderr, "Erreur fichier trop grand\n");
        	return 1;
        }
        input = (unsigned char*) malloc(sizeof(unsigned char) * input_len);
        fread(input, 1, input_len, Fd);
        fclose(Fd);
    }


    int i ;

	return 0;
}



