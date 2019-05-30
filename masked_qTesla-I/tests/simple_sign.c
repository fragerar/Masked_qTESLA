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
#include "../sign_gadgets.h"
#include "../base_gadgets.h"
#include "../utils.h"
#include "../sha3/fips202.h"
  
#if (OS_TARGET == OS_LINUX)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

#define MLEN 59


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

  for (i=0; i<NRUNS; i++){
    crypto_masked_keypair(msk, me, pk, seed);
    rejctrkg+=ctr_keygen;
  }

  // Print acceptance rate for keygen. The counter increased by PARAM_K for each try
  printf("Acceptance rate of Keygen : %.2f\n", (double)((PARAM_K+1)*NRUNS)/((double)rejctrkg)); fflush(stdout);
 
  for (i=0; i<NRUNS; i++)
  {
    randombytes(mi, MLEN);
    crypto_masked_sign(sm, &smlen, mi, MLEN, msk, me, seed);   
    rejctr+=ctr_sign;
    rejw+=rejwctr;
    rejyz+=rejyzctr;
  }
  
  printf("Acceptance rate of v\t  : %.2f\n",1/((rejw/NRUNS)+1));
  printf("Acceptance rate of z\t  : %.2f\n",1/((rejyz/(NRUNS+rejw))+1));
  printf("Acceptance rate of Signing: %.2f\n",(double)NRUNS/rejctr);
  printf("\n");
 
  return 0;
}



void test_hash(){
  int32_t r;
  masked r_m;


  int32_t mask, cL;
  unsigned char t, t2;
  int i;
  for(int j=0; j < 4194304; ++j){

    if (j%100000 == 0)
      printf("Iteration %u\n", j);
    i = j;
    // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q   
    mask = (PARAM_Q/2 - i) >> (RADIX32-1);                    
    i = ((i-PARAM_Q) & mask) | (i & ~mask);    

    cL = i & ((1<<PARAM_D)-1);
    // If cL > 2^(d-1) then cL -= 2^d
    mask = ((1<<(PARAM_D-1)) - cL) >> (RADIX32-1);                    
    cL = ((cL-(1<<PARAM_D)) & mask) | (cL & ~mask); 
    t = (unsigned char)((i - cL) >> PARAM_D);   



    r_m[0] = i;
    for(int k=1; k < N_SHARES; ++k) r_m[k] = 0;
    full_refresh_arith(r_m, r_m);
    t2 = masked_rounding(r_m);

    //printf("Rounding of %u : %u =?= %u => Well yes but actually...", i, t, t2);
    //if (t == t2) printf("Yes ! \n");
    //else         printf("No  ! \n");
    if (t != t2){ 
      printf("Rounding of");
      print_bits(j);
      printf(" : %u =?= %u => Well yes but actually...\n", t, t2);  
    }
  }

    

}




int main(void)
{
    unsigned int i, j;
    unsigned char r;
    int valid, response;
    //masked_poly y;
    
    srand(time(NULL));
    printf("Hello there\n");

    //test_hash();
   


    
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
