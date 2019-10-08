/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: NTT, modular reduction and polynomial functions
**************************************************************************************/

#include "poly.h"
#include "sha3/fips202.h"
#include "api.h"

extern poly zeta;
extern poly zetainv;


void poly_uniform(poly a, const unsigned char *seed)         
{ // Generation of polynomial "a"
  //unsigned int pos=0, i=0, nbytes = (PARAM_Q_LOG+7)/8;
  unsigned int i=0;
  //unsigned int nblocks=PARAM_GEN_A;
  unsigned char buf[SHAKE128_RATE*PARAM_GEN_A];
  uint16_t dmsp=0;

  cshake128_simple(buf, sizeof(int32_t)*PARAM_N, dmsp++, seed, CRYPTO_RANDOMBYTES);    
  
  for(i=0; i < PARAM_N; ++i){
    a[i]  = (buf[(i<<2)+0]<<0 );
    a[i] += (buf[(i<<2)+1]<<8 );
    a[i] += (buf[(i<<2)+2]<<16);
    a[i] += (buf[(i<<2)+3]<<24);
    a[i] = a[i]&(PARAM_Q-1);
  }
}


int32_t reduce(int64_t a)
{ // Montgomery reduction
  int64_t u;

  u = (a*PARAM_QINV) & 0xFFFFFFFF;
  u *= PARAM_Q;
  a += u;
  return (int32_t)(a>>32);
}


void ntt(poly a, const poly w)
{ // Forward NTT transform
  int NumoProblems = PARAM_N>>1, jTwiddle=0;

  for (; NumoProblems>0; NumoProblems>>=1) {
    int jFirst, j=0;
    for (jFirst=0; jFirst<PARAM_N; jFirst=j+NumoProblems) {
      sdigit_t W = (sdigit_t)w[jTwiddle++];
      for (j=jFirst; j<jFirst+NumoProblems; j++) {
        int32_t temp = reduce((int64_t)W * a[j+NumoProblems]);
        a[j + NumoProblems] = a[j] - temp;
        a[j] = temp + a[j];
      }
    }
  }
}

#if !defined(_qTESLA_I_)

int32_t barr_reduce(int32_t a)
{ // Barrett reduction
  int32_t u = ((int64_t)a*PARAM_BARR_MULT)>>PARAM_BARR_DIV;
  return a - (int32_t)u*PARAM_Q;
}

#endif

void nttinv(poly a, const poly w)
{ // Inverse NTT transform
  int NumoProblems = 1, jTwiddle=0;
  for (NumoProblems=1; NumoProblems<PARAM_N; NumoProblems*=2) {
    int jFirst, j=0;
    for (jFirst = 0; jFirst<PARAM_N; jFirst=j+NumoProblems) {
      sdigit_t W = (sdigit_t)w[jTwiddle++];
      for (j=jFirst; j<jFirst+NumoProblems; j++) {
        int32_t temp = a[j];
#if defined(_qTESLA_I_)
        a[j] = temp + a[j + NumoProblems];
#else
        if (NumoProblems == 16) 
          a[j] = barr_reduce(temp + a[j + NumoProblems]);
        else
          a[j] = temp + a[j + NumoProblems];
#endif
        a[j + NumoProblems] = reduce((int64_t)W * (temp - a[j + NumoProblems]));
      }
    }
  }

  for (int i = 0; i < PARAM_N/2; i++)
    a[i] = reduce((int64_t)PARAM_R*a[i]);
}


static void poly_pointwise(poly result, const poly x, const poly y)
{ // Pointwise polynomial multiplication result = x.y

  for (int i=0; i<PARAM_N; i++)
    result[i] = reduce((int64_t)x[i]*y[i]);
}


void poly_mul(poly result, const poly x, const poly y)
{ // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)
  // The input x is assumed to be in NTT form
  poly y_ntt;
    
  for (int i=0; i<PARAM_N; i++)
    y_ntt[i] = y[i];
  
  ntt(y_ntt, zeta);
  poly_pointwise(result, x, y_ntt);
  nttinv(result, zetainv);
}


void poly_add(poly result, const poly x, const poly y)
{ // Polynomial addition result = x+y

    for (int i=0; i<PARAM_N; i++)
      result[i] = x[i] + y[i];
}


void poly_add_correct(poly result, const poly x, const poly y)
{ // Polynomial addition result = x+y with correction

    for (int i=0; i<PARAM_N; i++) {
      result[i] = (x[i] + y[i])&(PARAM_Q-1);
      /*result[i] += (result[i] >> (RADIX32-1)) & PARAM_Q;    // If result[i] < 0 then add q
      result[i] -= PARAM_Q;
      result[i] += (result[i] >> (RADIX32-1)) & PARAM_Q;    // If result[i] >= q then subtract q*/
    }
}


void poly_sub_correct(poly result, const poly x, const poly y)
{ // Polynomial subtraction result = x-y with correction

    for (int i=0; i<PARAM_N; i++) {
      result[i] = (x[i] - y[i])&(PARAM_Q-1);
      //result[i] += (result[i] >> (RADIX32-1)) & PARAM_Q;    // If result[i] < 0 then add q
    }
}


void poly_sub_reduce(poly result, const poly x, const poly y)
{ // Polynomial subtraction result = x-y with Montgomery reduction

    for (int i=0; i<PARAM_N; i++)
      result[i] = reduce((int64_t)PARAM_R*(x[i] - y[i]));
}


/********************************************************************************************
* Name:        sparse_mul16
* Description: performs sparse polynomial multiplication
* Parameters:  inputs:
*              - const unsigned char* s: part of the secret key
*              - const uint32_t pos_list[PARAM_H]: list of indices of nonzero elements in c
*              - const int16_t sign_list[PARAM_H]: list of signs of nonzero elements in c
*              outputs:
*              - poly prod: product of 2 polynomials
*
* Note: pos_list[] and sign_list[] contain public information since c is public
*********************************************************************************************/
void sparse_mul16(poly prod, const int16_t *s, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H])
{
  int i, j, pos;
  int16_t *t = (int16_t*)s;

  for (i=0; i<PARAM_N; i++)
    prod[i] = 0;

  for (i=0; i<PARAM_H; i++) {
    pos = pos_list[i];
    for (j=0; j<pos; j++) {
        prod[j] = prod[j] - sign_list[i]*t[j+PARAM_N-pos];
    }
    for (j=pos; j<PARAM_N; j++) {
        prod[j] = prod[j] + sign_list[i]*t[j-pos];
    }
  }
}


/********************************************************************************************
* Name:        sparse_mul32
* Description: performs sparse polynomial multiplication 
* Parameters:  inputs:
*              - const int32_t* pk: part of the public key
*              - const uint32_t pos_list[PARAM_H]: list of indices of nonzero elements in c
*              - const int16_t sign_list[PARAM_H]: list of signs of nonzero elements in c
*              outputs:
*              - poly prod: product of 2 polynomials
*********************************************************************************************/
void sparse_mul32(poly prod, const int32_t *pk, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H])
{
  int i, j, pos;

  for (i=0; i<PARAM_N; i++)
    prod[i] = 0;
  
  for (i=0; i<PARAM_H; i++) {
    pos = pos_list[i];
    for (j=0; j<pos; j++) {
        prod[j] = prod[j] - sign_list[i]*pk[j+PARAM_N-pos];
    }
    for (j=pos; j<PARAM_N; j++) {
        prod[j] = prod[j] + sign_list[i]*pk[j-pos];
    }
  }
}




/*
*
* Karatsuba
*
*
*
*/


static void nmul(int32_t* p1, int32_t* p2, int32_t* out, int size){
    int i,j;
    for (i=0; i < 2*size-1; ++i) out[i] = 0;
    for (i=0; i < size; ++i){
        for(j=0; j < size; ++j)
            out[i+j] += p1[i]*p2[j];
    }
}



static void karatsuba(int32_t* p1, int32_t* p2, int32_t* out, int size){
    /*
     * (aX+b)*(a'X+b')
     * z1 = aa'
     * z2 = bb'
     * t1 = a+b
     * t2 = a'+b'
     * t3 = t1*t2
     * z3 = t3 - z1 - z2
     */


    if (size == 32){
        nmul(p1, p2, out, 32);
        return;
    }


    int i;    
    int32_t t1[size/2], t2[size/2], t3[size-1];
    int32_t z1[size-1], z2[size-1];


    
    karatsuba(p1+size/2, p2+size/2, z1, size/2); // z1 = aa'
    karatsuba(p1,        p2,        z2, size/2); // z2 = bb'

    // t1 t2
    for(i=0; i < (size/2);++i) {
        t1[i] = p1[i]+p1[i+size/2];
        t2[i] = p2[i]+p2[i+size/2];
    }

    karatsuba(t1, t2, t3, size/2);    

    for (i=0; i < size-1; ++i){
        t3[i] = t3[i] - z1[i];
        t3[i] = t3[i] - z2[i];
    }
    
   
    for(i=0; i < 2*size-1; i++) out[i] = 0;
    for(i=0; i < size-1; i++){
        out[i] += z2[i];
        out[i+size/2] += t3[i];
        out[i+size] += z1[i];
    }
}


void poly_mul_pot(poly out, poly p1, poly p2){
    int32_t temp[2*PARAM_N-1];
    int i;
    karatsuba(p1, p2, temp, PARAM_N);

    for(i=      0; i < PARAM_N; ++i)     out[i]          = temp[i]&(PARAM_Q-1);
    for(i=PARAM_N; i < 2*PARAM_N-1; ++i) out[i-PARAM_N]  = (out[i-PARAM_N] - temp[i])&(PARAM_Q-1);
    

}


void poly_sub_reduce_pot(poly result, const poly x, const poly y)
{ // Polynomial subtraction result = x-y with Montgomery reduction

    for (int i=0; i<PARAM_N; i++)
      result[i] = (x[i] - y[i])&(PARAM_Q-1);
}
