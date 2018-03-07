#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protect_buffer.h"

int main (int argc, char ** argv){





								//-e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]
								//-d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>


								int choix =0;
								choix = checkArg(argc, argv);
								printf("choix : %d\n",choix );


								if (choix ==1)
								{
																encrypt(argc,argv);
								}

								if (choix ==2)
								{
																decrypt(argc,argv);
								}

								return 0;
}
