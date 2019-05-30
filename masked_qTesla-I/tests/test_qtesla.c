/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: testing and benchmarking code
**************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "../random/random.h"
#include "cpucycles.h"
#include "../api.h"
#include "../poly.h"
#include "../pack.h"
#include "../sample.h"
#include "../params.h"
#include "../gauss.h"
#include "../sha3/fips202.h"
#include "../sign_gadgets.h"
#include "../base_gadgets.h"

#include <time.h>
  
#if (OS_TARGET == OS_LINUX)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

#define MLEN 59


static int cmp_llu(const void *a, const void*b)
{
  if (*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if (*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}


static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if (llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}


static unsigned long long average(unsigned long long *t, size_t tlen)
{
  unsigned long long acc=0;
  size_t i;
  for (i=0; i<tlen; i++)
    acc += t[i];
  return acc/(tlen);
}


static void print_results(const char *s, unsigned long long *t, size_t tlen)
{
  printf("%s", s);
  printf("\n");
  printf("median:  %llu ", median(t, tlen));  print_unit; printf("\n");
  printf("average: %llu ", average(t, tlen-1));  print_unit; printf("\n");
  printf("\n");
}


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

#ifdef COUNT
extern unsigned long long count_rand;
#endif

masked_poly msk, me;
unsigned char seed[CRYPTO_RANDOMBYTES];

 

int print_accrates()
{
  double rejw=.0, rejyz=.0, rejctr=.0, rejctrkg=.0;
  unsigned long long i;

  for (i=0; i<NRUNS; i++){
    crypto_sign_keypair(pk, sk);
    rejctrkg+=ctr_keygen;
  }

  // Print acceptance rate for keygen. The counter increased by PARAM_K for each try
  printf("Acceptance rate of Keygen : %.2f\n", (double)((PARAM_K+1)*NRUNS)/((double)rejctrkg)); fflush(stdout);
 
  for (i=0; i<NRUNS; i++)
  {
    randombytes(mi, MLEN);
    crypto_sign(sm, &smlen, mi, MLEN, sk);    
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



void timing_sign()

{

  randombytes(mi, MLEN);
  crypto_masked_keypair(msk, me, pk, seed);

  clock_t start_t, end_t;
  double total_t;
  unsigned long long start_cycles, stop_cycles;
  int i;


  start_t = clock();
  start_cycles = cpucycles();
  for(i=0; i< NRUNS; i++) {
      crypto_masked_sign(sm, &smlen, mi, MLEN, msk, me, seed);
  }
  stop_cycles = cpucycles();
  end_t = clock();
  total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
  printf("Total time taken by CPU: %f\n", total_t );
  printf("Time for one signature (s): %f\n",total_t/NRUNS);
  printf("Sig/sec: %f\n", NRUNS/total_t);
  printf("Avg cycles count: %llu\n", (stop_cycles-start_cycles)/NRUNS);
  printf("\n\n");


}

void timing_unmasked_sign()

{

  randombytes(mi, MLEN);
  crypto_sign_keypair(pk, sk);

  clock_t start_t, end_t;
  double total_t;
  unsigned long long start_cycles, stop_cycles;
  int i;


  start_t = clock();
  start_cycles = cpucycles();
  for(i=0; i< NRUNS; i++) {
      crypto_sign(sm, &smlen, mi, MLEN, sk);
  }
  stop_cycles = cpucycles();
  end_t = clock();
  total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
  printf("Total time taken by CPU: %f\n", total_t );
  printf("Time for one signature (s): %f\n",total_t/NRUNS);
  printf("Sig/sec: %f\n", NRUNS/total_t);
  printf("Avg cycles count: %llu\n", (stop_cycles-start_cycles)/NRUNS);
  printf("\n\n");


}


void test_gadgets(){
  unsigned char c_h[CRYPTO_C_BYTES], randomness[CRYPTO_SEEDBYTES], randomness_input[CRYPTO_RANDOMBYTES+CRYPTO_SEEDBYTES+HM_BYTES];
  uint32_t pos_list[PARAM_H];
  int16_t sign_list[PARAM_H], s_unmasked[PARAM_N], e_unmasked[PARAM_N];
  poly r;
  masked_poly y, v, Sc, z, Ec;
  unsigned long long cycles0[NTESTS];

  int a[MASKING_ORDER+1], b[MASKING_ORDER+1], c[MASKING_ORDER+1];

  int i;


  printf("=========================================================\n");
  printf("                    TEST GADGETS order %i (%i tests)\n", MASKING_ORDER, NTESTS);
  printf("=========================================================\n");


  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    RG(PARAM_B, a, RADIX32);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("RG: ", cycles0, NTESTS);

  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    masked_rounding(a);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("Masked round: ", cycles0, NTESTS);


  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    masked_well_rounded(a);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("Masked_WR: ", cycles0, NTESTS);



  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    masked_RS(a);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("Masked_RS: ", cycles0, NTESTS);


  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    sec_add(a,b,c);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("sec_add: ", cycles0, NTESTS);

  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    sec_and(a,b,c);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("sec_and: ", cycles0, NTESTS);


  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    full_xor(a);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("full_xor: ", cycles0, NRUNS);

  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    refresh(a, b);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("refresh: ", cycles0, NTESTS);

  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    full_refresh(a, b);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("full_refresh: ", cycles0, NTESTS);

  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    full_refresh_arith(a, b);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("full_refresh_arith: ", cycles0, NTESTS);

  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    sec_arith_bool_mod_p(a, b);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("sec_arith_bool_mod_q: ", cycles0, NTESTS);


  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    sec_bool_arith(a, b);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("sec_bool_arith: ", cycles0, NTESTS);


  for (i = 0; i < NTESTS; i++) {
    cycles0[i] = cpucycles();
    full_add_coef(a);
    cycles0[i] = cpucycles() - cycles0[i];
  }
  print_results("full_add_coef: ", cycles0, NTESTS);




}



int test_unmasked(){
  unsigned int i, j;
  unsigned char r;
  unsigned long long cycles0[NRUNS], cycles1[NRUNS], cycles2[NRUNS];
  int valid, response;
    
  printf("\n");
  printf("===========================================================================================\n");
  printf("Testing unmasked version of signature scheme qTESLA, system %s, tests for %d iterations\n", CRYPTO_ALGNAME, NRUNS);
  printf("===========================================================================================\n");


  for (i = 0; i < NRUNS; i++) {
    randombytes(mi, MLEN);

    cycles0[i] = cpucycles();
    crypto_sign_keypair(pk, sk);
    cycles0[i] = cpucycles() - cycles0[i];

    cycles1[i] = cpucycles();
    crypto_sign(sm, &smlen, mi, MLEN, sk);
    cycles1[i] = cpucycles() - cycles1[i];

    cycles2[i] = cpucycles();
    valid = crypto_sign_open(mo, &mlen, sm, smlen, pk);
    cycles2[i] = cpucycles() - cycles2[i];
    
    if (valid != 0) {
      printf("Signature verification FAILED. \n");
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
  }
  printf("Signature tests PASSED... \n\n");

  print_results("qTESLA keygen: ", cycles0, NRUNS);
  print_results("qTESLA sign: ", cycles1, NRUNS);
  print_results("qTESLA verify: ", cycles2, NRUNS);


  return 0;

}


int test_masked(){

  unsigned int i, j;
  unsigned char r;
  unsigned long long cycles1[NRUNS];
    
    
  clock_t start_t, end_t;
  double total_t;
  unsigned long long start_cycles, stop_cycles; 

  printf("\n");
  printf("====================================================================================================================\n");
  printf("Testing masked order %i version of signature scheme qTESLA, system %s, tests for %d iterations\n", MASKING_ORDER, CRYPTO_ALGNAME, NRUNS);
  printf("====================================================================================================================\n");
  randombytes(mi, MLEN);
  
  start_t = clock();

  for (i = 0; i < NRUNS; i++) {

    cycles1[i] = cpucycles();
    crypto_masked_sign(sm, &smlen, mi, MLEN, msk, me, seed);
    cycles1[i] = cpucycles() - cycles1[i];
  }
  end_t = clock();
  total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;

  print_results("qTESLA masked sign: ", cycles1, NRUNS);  
  printf("Total time taken by CPU: %f\n", total_t );
  printf("Time for one signature (s): %f\n",total_t/NRUNS);
  printf("Sig/sec: %f\n", NRUNS/total_t);
  printf("\n\n");

  return 0;

}


int test_correctness(){

  unsigned int i, j;
  unsigned char r;
  unsigned long long cycles0[NRUNS], cycles1[NRUNS], cycles2[NRUNS];
  int valid, response;
  const int ITER = 50;
    
  clock_t start_t, end_t;
  double total_t;
  unsigned long long start_cycles, stop_cycles; 

  printf("\n");
  printf("====================================================================================================================\n");
  printf("Testing correctness masked order %i version of signature scheme qTESLA %i iterations \n", MASKING_ORDER, ITER);
  printf("====================================================================================================================\n");
  randombytes(mi, MLEN);

  for (i = 0; i < ITER; i++) {


    crypto_masked_keypair(msk, me, pk, seed);    

    crypto_masked_sign(sm, &smlen, mi, MLEN, msk, me, seed);

    valid = crypto_sign_open(mo, &mlen, sm, smlen, pk);



    if (valid != 0) {
      printf("Signature verification FAILED. \n");
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
  }
  
  printf("Signature tests PASSED... \n\n");
  return 0;

}

#ifdef COUNT

int test_count(){


  unsigned int i, j;
  unsigned char r;
  int valid, response;

  count_rand = 0;
  

  printf("\n");
  printf("====================================================================================================================\n");
  printf("Testcount\n");
  printf("====================================================================================================================\n");
  randombytes(mi, MLEN);

  for (i = 0; i < NRUNS; i++) {


    crypto_masked_keypair(msk, me, pk, seed);    
    crypto_masked_sign(sm, &smlen, mi, MLEN, msk, me, seed);
    valid = crypto_sign_open(mo, &mlen, sm, smlen, pk);

    if (valid != 0) {
      printf("Signature verification FAILED. \n");
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
  }
  printf("Signature tests PASSED... \n\n");

  printf("Average rand: %f\n", (float)count_rand/NRUNS);
  return 0;

}
#endif


int main(void)
{

  srand(time(NULL));
  srand48(time(NULL));
  lrand48();
  seed_xoshiro();
  
  for(int i =0; i < 5; ++i) printf("Rand: %u\n", rand_uint32());

	
  #if MASKING_ORDER == 0
    test_unmasked();
    timing_unmasked_sign();
  #else
		//test_correctness();
    //test_masked();
    //test_gadgets();    
    test_count();
  #endif  

  return 0;
}
