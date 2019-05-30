#include "sign_gadgets.h"
#include "base_gadgets.h"

#include "utils.h"
#include "params.h"


void RG(int k_val, int* a, const int BITSIZE){

  /*
   *  Input:
   *    k_val: integer
   *    BITSIZE: constant integer
   *  Output:
   *    a: arithmetic masking of an integer in [-k_val, k_val]
   *       sampled by performing rejection sampling on BITSIZE bits
   */


  int i, rej_b;
  masked k = {-2*k_val+1,};
  masked x, x_zero, delta, b;

  do{

    for(i=0; i < N_SHARES; ++i) x_zero[i] = rand()&((1<<BITSIZE)-1);        
    refresh(x_zero, x);

    sec_add(x, k, delta);
    for(i=0; i < N_SHARES; ++i) b[i] = (unsigned)delta[i] >> (RADIX32-1); 
    rej_b = full_xor(b);

  } while (!rej_b);

  sec_bool_arith(x, a);

}


void DG(masked_poly y, int k, const int BITSIZE){

  /*
   *  Input:
   *    k: integer
   *    BITSIZE: constant integer
   *  Output:
   *    y: a masked polynomial with coefficients in [-k, k] 
   *       sampled by performing rejection sampling on BITSIZE bits
   */

    int i, j;
    masked shares;

    for(j=0; j < PARAM_N; ++j){
      RG(k, shares, BITSIZE);
      shares[0] -= k;
      for(i=0; i < N_SHARES; ++i) y[i][j] = mod_q(shares[i]);
    }
}


void abs_val(int* x, int* abs_x, int SB_POSITION){

	/*
	 *  Input:	
	 *    x: boolean masking of an integer
   *    SB_POSITION: integer 
	 *  Output:
   *    abs_x: boolean masking of |x mod 2^SB_POSITION|
	 */

  int i;
	masked mask;

 	for(i=0; i < N_SHARES; ++i) mask[i] = (x[i]<<(RADIX32 - SB_POSITION)) >> (RADIX32-1); // ABS
	full_refresh(x, x);
  sec_add(x, mask, abs_x);

  for(i=0; i < N_SHARES; ++i) abs_x[i] = (abs_x[i] ^ mask[i])&((1<<SB_POSITION)-1);
}


int full_RS(masked_poly p){
  
  /*
   *  Input: 
   *    p: a polynomial in arithmetic masked form
   *  Output: 
   *    1 if all coefficients are well rounded else 0
   */

    int i,j;
    masked p_coef;

    for(i=0; i < PARAM_N; ++i){
        for(j=0; j < N_SHARES; ++j) p_coef[j] = p[j][i];
        if (masked_RS(p_coef) == 0) return 0;  
        
    }
    return 1;
}


int masked_RS(int* a){
  /*   
   *  Input : 
   *    a : arithmetical masking of an integer A
   *  Output :
   *    1 if |A| <= PARAM_B-PARAM_S       
   *    0 otherwise                     
   */  

  int i;
  masked a_prime, b, x;
  static masked SUP = {-PARAM_B+PARAM_S-1,};

  sec_arith_bool_mod_p(a, a_prime);

  abs_val(a_prime, x, EXACT_Q_LOG);

  sec_add(x, SUP, x);
  for(i=0; i < N_SHARES; ++i) b[i] = ((unsigned)x[i]>>(RADIX32-1));

  return full_xor(b);

}

int full_WR(masked_poly p){
  /*
   *  Input: 
   *    p: a polynomial in arithmetic masked form
   *  Output: 
   *    1 if all coefficients are well rounded else 0
   */

  int i,j;
  masked p_coef;

  for(i=0; i < PARAM_N; ++i){
      for(j=0; j < N_SHARES; ++j) p_coef[j] = p[j][i];          
      if (masked_well_rounded(p_coef) == 0) return 0;
  }
  return 1;
}



int masked_well_rounded(int* a){

  /*   
   *  Input : 
   *    a : arithmetical masking of an integer A
   *  Output :
   *    1 if |A| < Q/2 - PARAM_E and |[A]_L| < 2^{PARAM_D-1} - PARAM_E        
   *    0 otherwise                     
   */  


  int i;
  masked a_prime, b, b_prime, x;
  static masked SUP_Q = {-PARAM_Q/2+PARAM_E,};
  static masked SUP_D = {-(1<<(PARAM_D-1))+PARAM_E,};

  sec_arith_bool_mod_p(a, a_prime);

  abs_val(a_prime, x, EXACT_Q_LOG);

  sec_add(x, SUP_Q, x);
  for(i=0; i < N_SHARES; ++i) b[i] = ((unsigned)x[i]>>(RADIX32-1));
  

  full_refresh(a_prime, a_prime);
  for(i=0; i < N_SHARES; ++i) a_prime[i] &= ((1<<PARAM_D)-1);

  abs_val(a_prime, x, PARAM_D);

  sec_add(x, SUP_D, x);
  for(i=0; i < N_SHARES; ++i) b_prime[i] = ((unsigned)x[i]>>(RADIX32-1));

  sec_and(b, b_prime, b);
  return full_xor(b);

}

unsigned char masked_rounding(int* a){

  /*   
   *  Input : 
   *    a : arithmetical masking of an integer A
   *  Output :
   *    [A]_M = (A mod+- q - [A]_L)/(2^PARAM_D)
   *    See paper                       
   */  


  int i;
  masked b, a_prime;
  static masked MINUS_Q_HALF = {-PARAM_Q/2-1,};  
  static masked CONST = {(1<<(PARAM_D-1))-1,};

  sec_arith_bool_mod_p(a, a_prime);


  // if a > Q/2

  sec_add(a_prime, MINUS_Q_HALF,b);
  b[0] = ~b[0];
  for(i=0; i < N_SHARES; ++i) b[i] = (b[i]>>(RADIX32-1)) << EXACT_Q_LOG; //With power of two modulus, x-q is just setting high bits to one
  // a -= Q
  for(i=0; i < N_SHARES; ++i) a_prime[i] = a_prime[i]^b[i]; 

  sec_add(a_prime, CONST, a_prime);
  for(i=0; i < N_SHARES; ++i) a_prime[i] = a_prime[i] >> PARAM_D;
  return (unsigned char)full_xor(a_prime);


}
