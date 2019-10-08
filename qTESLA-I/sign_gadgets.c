#include "sign_gadgets.h"
#include "base_gadgets.h"

#include "utils.h"
#include "params.h"

#include "CDT64.h"


void masked_gaussian_poly(masked_poly s){
  masked v;
  int i,j;
  for(j=0; j < PARAM_N; ++j){
    gaussian(v);
    for(i=0; i < N_SHARES; ++i) s[i][j] = v[i];
  }
}


void gaussian(int* a){
  int i,j;
  masked128 r, delta;
  masked b, b_p;
  for (i=0; i < N_SHARES; ++i){
    r[i]   = rand();
    r[i] <<= 32;
    r[i]  ^= rand();
  } 

  masked x = {0}; 

  for(j=1; j < CDT_SIZE; ++j){
    masked128 k = {(int128_t)-cdt_v[j]};
    sec_add128(r,k, delta);

    for(i=0; i < N_SHARES; ++i) {
      b[i] = (int)(delta[i] >> 127); 
    }
    b[0] = ~b[0]; 
    masked J = {j-1}; 
    b_p[0] = ~b[0]; 
    for(i=1; i < N_SHARES; ++i) b_p[i] = b[i];

    sec_and(J, b, b);
    sec_and(x, b_p, b_p);
    for(i=0; i < N_SHARES; ++i) x[i] = b_p[i] ^ b[i];
  }
  sec_bool_arith(x, a);

}

void masked_sign_choice(masked_poly p){
  /*
    Assign a random sign to each coefficient of the masked polynomial
    This function is needed because the table is use to sample only half of the gaussian
  */
  int i,j;
  masked mask, sign;
  masked temp,x;



  for(j=0; j < PARAM_N; ++j){

    for(i=0; i < N_SHARES; ++i) temp[i]=p[i][j];
    sec_arith_bool_mod_p(temp,x);
    for(i=0; i < N_SHARES; ++i) sign[i] = (rand()&1); // 0 or 1
    for(i=0; i < N_SHARES; ++i) mask[i] = -sign[i]; // 0x00000000 if sign=0, 0x11111111 if sign=1
    for(i=0; i < N_SHARES; ++i) x[i] ^= mask[i];
    sec_add(x, sign, x);
    sec_bool_arith(x,temp);
    for(i=0; i < N_SHARES; ++i) p[i][j] = temp[i];
  }
}

int masked_checkES(masked_poly p, unsigned bound){
  int i,j,k,check,limit=PARAM_N;
  masked list[PARAM_N];
  masked current, next, delta, exchange, not_exchange, temp;
  static masked ONE={1};
  masked BOUND={-bound};
  masked sum={0};

  for(i=0; i < PARAM_N; ++i) for(j=0; j < N_SHARES; ++j) list[i][j] = p[j][i];

  for(j=0; j < PARAM_H; ++j){ // PARAM_H bubble sort iterations
    for(i=0; i < limit-1; ++i){
      // Next lines compute masked two's complement
      delta[0] = (list[i][0] ^ (-1)); 
      for(k=1; k < N_SHARES; ++k) delta[k] = list[i][k];
      sec_add(delta, ONE, delta);

      // list[i+1] - list[i]
      sec_add(delta, list[i+1], delta);

      for(k=0; k < N_SHARES; ++k) {
        exchange[k] = (delta[k] >> (RADIX32-1)); // If negative, delta is 0x11111111 => exchange
        not_exchange[k] = exchange[k];
      }
      not_exchange[0] = ~exchange[0];

      sec_and(exchange, list[i+1], current);
      sec_and(not_exchange, list[i], temp);
      for(k=0; k < N_SHARES; ++k) current[k] = current[k] ^ temp[k]; // (list[i+1] and exchange) or (list[i] and not exchange)
      
      sec_and(exchange, list[i], next);
      sec_and(not_exchange, list[i+1], temp);
      for(k=0; k < N_SHARES; ++k) next[k] = next[k] ^ temp[k]; // (list[i] and exchange) or (list[i+1] and not exchange)
      
      for(k=0; k < N_SHARES; ++k){
        list[i][k] = current[k];
        list[i+1][k] = next[k];
      }
    }
    sec_add(sum, list[limit-1], sum);
    limit--;
  }

  sec_add(sum, BOUND, delta);
  for(i=0; i < N_SHARES; ++i) delta[i] = ((unsigned)delta[i]) >> (RADIX32-1);
  check = full_xor(delta);
  return check;


}


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
