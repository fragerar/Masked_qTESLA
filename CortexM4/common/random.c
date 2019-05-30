/******************************************************
* Hardware-based random number generation function
*******************************************************/ 

#include "random.h"
#include <stdlib.h>


void randombytes(unsigned char* random_array, unsigned int nbytes)
{
  //randombytes_internal(random_array, nbytes);
  for(int i=0; i < nbytes; ++i) random_array[i] = rand();
}


