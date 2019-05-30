#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../random/random.h"
#include "cpucycles.h"
#include "../api.h"
#include "../poly.h"
#include "../pack.h"
#include "../sample.h"
#include "../params.h"
#include "../gauss.h"
#include "../gadget.h"
#include "../utils.h"
#include "../sha3/fips202.h"
  
#if (OS_TARGET == OS_LINUX)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

#define MLEN 59
#define NRUNS 1000
#define NTESTS 1000


unsigned char mi[MLEN];
unsigned char mo[MLEN+CRYPTO_BYTES];
unsigned char sm[MLEN+CRYPTO_BYTES];

unsigned char pk[CRYPTO_PUBLICKEYBYTES];
unsigned char sk[CRYPTO_SECRETKEYBYTES];


unsigned long long smlen, mlen;

extern unsigned long long rejwctr;
extern unsigned long long rejyzctr;
extern unsigned long long ctr_keygen;
extern unsigned long long ctr_sign;

masked_poly msk, me;
poly t;


unsigned char seed[CRYPTO_RANDOMBYTES];


int print_accrates()
{
  int r;
  double rejw=.0, rejyz=.0, rejctr=.0, rejctrkg=.0;
  unsigned long long i, j;

  for (i=0; i<NTESTS; i++){
    crypto_masked_keypair(msk, me, pk, seed);
    rejctrkg+=ctr_keygen;
  }

  // Print acceptance rate for keygen. The counter increased by PARAM_K for each try
  printf("Acceptance rate of Keygen : %.2f\n", (double)((PARAM_K+1)*NTESTS)/((double)rejctrkg)); fflush(stdout);
 
  for (i=0; i<NTESTS; i++)
  {
    randombytes(mi, MLEN);
    crypto_masked_sign(sm, &smlen, mi, MLEN, msk, me, seed);   
    rejctr+=ctr_sign;
    rejw+=rejwctr;
    rejyz+=rejyzctr;
  }
  
  printf("Acceptance rate of v\t  : %.2f\n",1/((rejw/NTESTS)+1));
  printf("Acceptance rate of z\t  : %.2f\n",1/((rejyz/(NTESTS+rejw))+1));
  printf("Acceptance rate of Signing: %.2f\n",(double)NTESTS/rejctr);
  printf("\n");
 
  return 0;
}




int main(void)
{
    unsigned int i, j;
    unsigned char r;
    int valid, response;
    masked_poly y;
    
    srand48(time(NULL));

    
    
    printf("Hello there\n");

    print_accrates();

    

    randombytes(mi, MLEN);

    crypto_masked_keypair(msk, me, pk, seed);

    

    

    crypto_masked_sign(sm, &smlen, mi, MLEN, msk, me, seed);
  
    printf("\n \n \n");

    valid = crypto_sign_open(mo, &mlen, sm, smlen, pk);

    if (valid != 0) {
      printf("Signature verification FAILED. \n");
      printf("Error %i", valid);
      return -1;
    } else if (mlen != MLEN) {
      printf("crypto_sign_open returned BAD message length. \n");
      return -1;
    }

    for (j = 0; j < mlen; j++) {
      if (mi[j] != mo[j]) {
        printf ("crypto_sign_open returned BAD message value. \n");
        return -1;
      }
    }

    // Change something in the signature somewhere    
    randombytes(&r, 1);
    sm[r % (MLEN+CRYPTO_BYTES)] ^= 1;
    response = crypto_sign_open(mo, &mlen, sm, smlen, pk);
    if (response == 0) {
      printf("Corrupted signature VERIFIED. \n");
      return -1;
    }
  
    printf("Signature tests PASSED... \n\n");


    printf("Reject z: %llu\nReject w: %llu\n", rejyzctr, rejwctr);

		
    return 0;

}  
