#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protect_buffer.h"

int main (int argc, char ** argv)
{
	int choix =0;
	choix = checkArg(argc, argv);
	if (choix ==1)
	{
		encrypt(argc,argv);
	}

	else if (choix ==2)
	{
		decrypt(argc,argv);
	}
	else 
	{
		help();
	}
	return 0;
}
