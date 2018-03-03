#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protect_buffer.h"

int main (int argc, char ** argv){
	

	unsigned char *IV, *Kc, *input,*output,*sha_output;
	unsigned int input_len =0,output_len=0,sha_output_len=0;

	if (genKc(&Kc) !=0)
	{
		return 1;
	}

	if (genIV(&IV) !=0)
	{
		return 1;
	}

	if (loadInput(&input,&input_len,argv[1]) != 0)
	{
		return 1;
	}

	if (chiffre_buffer(&output,&output_len,input,input_len,Kc,IV) !=0)
	{
		return 1;
	}

	if (signeKpub(&sha_output, sha_output_len, argv[2]) != 0)
	{
		return 1;
	}


	if (chiffreKc(&sha_output, sha_output_len, Kc, argv[2]) != 0)
	{
		return 1;
	}










	int i;
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
	printf("\n");


	return 0;
}











