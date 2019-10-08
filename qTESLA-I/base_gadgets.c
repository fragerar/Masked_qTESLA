#include "base_gadgets.h"
#include "utils.h"
#include "random/random.h"
#include "params.h"

#ifdef COUNT
unsigned long long count_rand;
#endif



static int secXOR(int x, int y, int u){
	return x ^ y ^ u;

}

static int secSHIFT(int x, int s, int t, int j){
	int y;
	y = t ^ (x << j);
	y = y ^ (s << j);
	return y; 
}
int order_1_AND(int x, int y, int s, int t, int u){
	/*
	 *
	 *
	 * https://eprint.iacr.org/2014/891
	*/
	int z;
	z = u ^ (x & y);
	z = z ^ (x & t);
	z = z ^ (s & y);
	z = z ^ (s & t);
	return z;
}

void goubin_bool_arith(int* bool_x, int* arith_x){
	/*
	 *
	 * http://www.goubin.fr/papers/arith-final.pdf
	 */

	int g = rand_uint32();
#ifdef COUNT
  	count_rand++;
#endif
	int t = bool_x[0] ^ g;
	t = t - g;
	t = t ^ bool_x[0];
	g = g ^ bool_x[1];
	arith_x[0] = bool_x[0] ^ g;
	arith_x[0] = arith_x[0] - g;
	arith_x[0] = arith_x[0] ^ t;
	arith_x[1] = bool_x[1];
	
}


void goubin_arith_bool(int* arith_x, int* bool_x){

	/*
 	 *
	 *	
	 * http://www.goubin.fr/papers/arith-final.pdf
	 */
	
	int a = arith_x[0];
	int r = arith_x[1];
	int x_p, g, t, o;
	g = rand_uint32();
	#ifdef COUNT
		count_rand++;
	#endif
	t = 2*g;
	x_p = g ^ r;
 	o = g & x_p;
	x_p = t ^ a;
	g = g ^ x_p;
	g = g & r;
	o = o ^ g;
	g = t & a;
	o = o ^ g;
	for(int i = 0; i < RADIX32-2; ++i){
		g = t & r;
		g = g ^ o;
		t = t & a;
		g = g ^ t;
		t = 2*g;
	}
	bool_x[0] = x_p ^ t;
	bool_x[1] = r;


}


void order_1_add(int* x, int* y, int* z){
	/*
	 * Secure addition of boolean shares of x and y specialized for masking of order 1
	 * https://eprint.iacr.org/2014/891
	 */


	int t, u, x_p, y_p, z_p, r, s, P, G, H, U;
	x_p = x[0]; s = x[1];
	y_p = y[0]; r = y[1];
	t = rand_uint32(); u = rand_uint32();
  #ifdef COUNT
  	count_rand += 2;
  #endif

	P = secXOR(x_p, y_p, r);
	G = order_1_AND(x_p, y_p, s, r, u);
	G = G ^ s;
	G = G ^ u;
	for(int i = 1; i <= W_ZERO_LOG-1; ++i){
		H = secSHIFT(G, s, t, 1<<(i-1));
		U = order_1_AND(P,H,s,t,u);
		G = secXOR(G, U, u);
		H = secSHIFT(P, s, t, 1<<(i-1));
		P = order_1_AND(P, H, s, t, u);
		P = P ^ s;
		P = P ^ u;
	}

	H = secSHIFT(G,s,t, (1<<(W_ZERO_LOG-1)));
	U = order_1_AND(P,H,s,t,u);
	G = secXOR(G, U, u);
	z_p = secXOR(y_p, x_p, s);
	z_p = z_p ^ (2*G);
	z_p = z_p ^ (2*s);
	z[0] = z_p;
	z[1] = r;
}


void refresh_masks_n(int* x, int* y, const int N){
	/*
	 * Variable size refresh of masks
	 *
	 */

	int r;
	y[N-1] = x[N-1];
	for(int i=0; i <  N-1; ++i){
		r = rand_uint32();
		#ifdef COUNT
			count_rand++;
		#endif
		y[i] = x[i] ^ r;
		y[N-1] = y[N-1] ^ r;
	}
}



void HO_bool_arith(int* bool_x, int* arith_x, const int N){
	/*
	 * High order boolean to arithmetic masking conversion of value x
	 * INPUT: boolean masking of x, number of shares N
	 * OUTPUT: arithmetic masking of x
	 * See 2017/252
	 */

	if (N==2)	{
		goubin_bool_arith(bool_x, arith_x);
		return;
	}	
	int x[N+1], a[N+1], b[N], c[N], d[N], e[N-1], f[N-1], A[N-1], B[N-1];

	for(int i=0; i < N; ++i) x[i] = bool_x[i];
	x[N] = 0;
	refresh_masks_n(x, a, N+1);
	b[0] = ((~N & 1)*a[0]) ^ ((a[0] ^ a[1]) - a[1]); 
	for(int i=1; i < N; ++i)
		b[i] = (a[0] ^ a[i+1]) - a[i+1];
	
	refresh_masks_n(a+1, c, N);
	refresh_masks_n(b,   d, N);

	for(int i = 0; i < N-2; ++i) e[i] = c[i];
	for(int i = 0; i < N-2; ++i) f[i] = d[i];


	e[N-2] = c[N-2] ^ c[N-1];
	f[N-2] = d[N-2] ^ d[N-1];

	HO_bool_arith(e, A, N-1);
	HO_bool_arith(f, B, N-1);

	for(int i = 0; i < N-2; ++i) arith_x[i] = A[i] + B[i];
	arith_x[N-2] = A[N-2];
	arith_x[N-1] = B[N-2];

}

void expand(int* x, int* out, const int N){
	/*
	 * Function expanding N shares into 2N shares 
	 * INPUT: boolean masking of value x
	 * OUTPUT: boolean masking of value x with twice many shares in out.
	 */
	int r;
	for(int i=0; i < N; ++i){
		r=rand_uint32();
		#ifdef COUNT
			count_rand++;
		#endif
		out[2*i    ] = x[i] ^ r;
		out[2*i + 1] = r;
	}
}

void sec_and_vs(int* x, int* y, int* res, const int N)
{	
	/*
	 * Variable size masked "and" operation beetween two boolean masking of values x and y
	 * INPUT: boolean masking of x and y, number of shares
	 * OUTPUT: writes boolean masking of x & y in res
	 */
	


    int r[N];
    int i, j, z_ij, z_ji;
    for(i=0; i < N; ++i) r[i] = x[i] & y[i];
    for(i=0; i < N; ++i)
        for(j=i+1; j < N; ++j){
            z_ij  = rand_uint32();
  #ifdef COUNT
            count_rand++;
  #endif
            z_ji  = (x[i] & y[j]) ^ z_ij;
            z_ji ^= (x[j] & y[i]);
            r[i] ^= z_ij;
            r[j] ^= z_ji;            
        }
    for(i=0; i < N; ++i) res[i] = r[i];

}

void refresh_vs(int* x, int* res, const int N)

{


    int i,j,r;
    for(i=0; i < N; ++i) res[i] = x[i];
    for(i=0; i < N; ++i)
        for(j=i+1; j < N; ++j){
            r = rand_uint32();
#ifdef COUNT
            count_rand++;
#endif
            res[i] ^= r;
            res[j] ^= r;
        }
}

void sec_add_vs(int* x, int* y, int* z, const int N)
{


    int p[N], g[N], a[N], a_prime[N];
    int i, j, pow;

    for(i=0; i < N; ++i) p[i] = x[i] ^ y[i];
    sec_and_vs(x, y, g, N);
    for(j=1; j <= W_ZERO_LOG-1; ++j){
        pow = 1<<(j-1);
        for(i=0; i < N; ++i) a[i] = (g[i] << pow); //!!!
        sec_and_vs(a, p, a, N);
        for(i=0; i < N; ++i) g[i] ^= a[i];
        for(i=0; i < N; ++i) a_prime[i] = (p[i] << pow);
        refresh_vs(a_prime, a_prime, N);
        sec_and_vs(p, a_prime, p, N);
    }
    for(i=0; i < N; ++i) a[i] = (g[i] << (1<<(W_ZERO_LOG-1))); //!!!
    sec_and_vs(a, p, a, N);
    for(i=0; i < N; ++i) g[i] ^= a[i];
    for(i=0; i < N; ++i) z[i] = x[i]^y[i]^(g[i]<<1);
	
}


void convert_A_B(int* arith_x, int* bool_x, const int N){
	/*
	 * Arithmetic to boolean masking conversion on N shares
	 * 
	 * Non power of two adaptation of http://www.crypto-uni.lu/jscoron/publications/secconvorder.pdf
	 */
	if (N == 1){
		bool_x[0] = arith_x[0];
		return;
	}

	int HALF = (N+1)/2;
	int x[HALF], x_p[2*HALF], y[HALF], y_p[2*HALF]; 
	convert_A_B(arith_x, x, HALF);
	expand(x, x_p, HALF);


	convert_A_B(arith_x+HALF, y, N/2);
	expand(y, y_p, N/2);

	if(N%2 == 1){
		y_p[2*HALF-1] = 0;
		y_p[2*HALF-2] = 0;
		x_p[2*HALF-2] ^= x_p[2*HALF-1];
	}

	sec_add_vs(x_p, y_p, bool_x, N);

}



void refresh(int* x, int* res)
/// VERIFIED : does the following : 
/*  Input : 
*          x : boolean masking of an integer X
*   Output :
*          res : boolean masking of an integer RES such that
*                             X = RES            
*/
{



    int i,j,r;
    for(i=0; i < N_SHARES; ++i) res[i] = x[i];
    for(i=0; i < N_SHARES; ++i)
        for(j=i+1; j < N_SHARES; ++j){
            r = rand_uint32();
#ifdef COUNT
            count_rand++;
#endif
            res[i] ^= r;
            res[j] ^= r;
        }
    
}


void refresh128(__int128_t* x, __int128_t* res)
/// VERIFIED : does the following : 
/*  Input : 
*          x : 128-bit boolean masking of an integer X
*   Output :
*          res : 128-bit boolean masking of an integer RES such that
*                             X = RES            
*/
{



    int i,j;
    __int128_t r;
    for(i=0; i < N_SHARES; ++i) res[i] = x[i];
    for(i=0; i < N_SHARES; ++i)
        for(j=i+1; j < N_SHARES; ++j){
            r = ((__int128_t)rand_uint32()<<96) ||((__int128_t)rand_uint32()<<64) || ((__int128_t)rand_uint32()<<32) || rand_uint32();
            res[i] ^= r;
            res[j] ^= r;
        }
    
}


void full_refresh(int* x, int* res){
/// VERIFIED : does the following : 
/* It is the SNI version of refresh
*   Input : 
*          x : boolean masking of an integer X
*   Output :
*          res : boolean masking of an iteger RES such that
*                             X = RES            
*/

    int i,j,r;
    for(i=0; i < N_SHARES; ++i) res[i] = x[i];
    for(i=0; i < N_SHARES; ++i)
        for(j=1; j < N_SHARES; ++j){
            r = rand_uint32();
#ifdef COUNT
            count_rand++;
#endif

            res[0] ^= r;
            res[j] ^= r;            
        }
    }


void full_refresh_arith(int* x, int* res)
/// VERIFIED : does the following : 
/* It is the SNI version of refresh
*   Input : 
*          x : arith masking of an integer X
*   Output :
*          res : arithmetical masking of an integer RES such that
*                             X = RES            
*/
{
    int i,j,r;
    for(i=0; i < N_SHARES; ++i) res[i] = x[i];
    for(i=0; i < N_SHARES; ++i)
        for(j=1; j < N_SHARES; ++j){
            r = rand()&(PARAM_Q-1); 
            res[0] = mod_q(res[0]+r);
            res[j] = mod_q(res[j]-r);     
        }
}




void sec_and(int* x, int* y, int* res)
/// VERIFIED : does the following : 
/*  Input : 
*          x : boolean masking of an integer X
*          y : boolean masking of an integer Y
*   Output :
*          res : boolean masking of an integer Z such that
*                             X&Y = res            
*/
{


#if OPTI == 1 && MASKING_ORDER == 1
    int u = rand_uint32();
#ifdef COUNT
		count_rand++;
#endif
    int z;
    z = u ^ (x[0] & y[0]);
    z = z ^ (x[0] & y[1]);
    z = z ^ (x[1] & y[0]);
    z = z ^ (x[1] & y[1]);
    res[0] = z;
    res[1] = u;

#else
    masked r;
    int i, j, z_ij, z_ji;
    for(i=0; i < N_SHARES; ++i) r[i] = x[i] & y[i];
    for(i=0; i < N_SHARES; ++i)
        for(j=i+1; j < N_SHARES; ++j){
            z_ij  = rand_uint32();
  #ifdef COUNT
            count_rand++;
  #endif
            z_ji  = (x[i] & y[j]) ^ z_ij;
            z_ji ^= (x[j] & y[i]);
            r[i] ^= z_ij;
            r[j] ^= z_ji;            
        }
    for(i=0; i < N_SHARES; ++i) res[i] = r[i];
#endif
}


void sec_and128(__int128_t* x, __int128_t* y, __int128_t* res)
/// VERIFIED : does the following : 
/*  Input : 
*          x : 128-bit boolean masking of an integer X
*          y : 128-bit boolean masking of an integer Y
*   Output :
*          res : 128-bit boolean masking of an integer Z such that
*                             X&Y = res            
*/
{

    masked128 r;
    int i, j;
    __int128_t z_ij, z_ji;
    for(i=0; i < N_SHARES; ++i) r[i] = x[i] & y[i];
    for(i=0; i < N_SHARES; ++i)
        for(j=i+1; j < N_SHARES; ++j){
            z_ij  = ((__int128_t)rand_uint32()<<96) ||((__int128_t)rand_uint32()<<64) || ((__int128_t)rand_uint32()<<32) || rand_uint32();
            z_ji  = (x[i] & y[j]) ^ z_ij;
            z_ji ^= (x[j] & y[i]);
            r[i] ^= z_ij;
            r[j] ^= z_ji;            
        }
    for(i=0; i < N_SHARES; ++i) res[i] = r[i];

}





void sec_add(int* x, int* y, int* z)
/// VERIFIED : does the following : 
/*  Input : 
*          x : arithmetical masking of an integer X
*          y : arithmetical masking of an integer Y
*   Output :
*          z : arithmetical masking of an integer Z such that
*                             X+Y=Z              
*/{

#if OPTI == 1 && MASKING_ORDER == 1
    order_1_add(x, y, z);
#else

    masked p, g, a, a_prime;
    int i, j, pow;

    for(i=0; i < N_SHARES; ++i) p[i] = x[i] ^ y[i];
    sec_and(x, y, g);
    for(j=1; j <= W_ZERO_LOG-1; ++j){
        pow = 1<<(j-1);
        for(i=0; i < N_SHARES; ++i) a[i] = (g[i] << pow); //!!!
        sec_and(a, p, a);
        for(i=0; i < N_SHARES; ++i) g[i] ^= a[i];
        for(i=0; i < N_SHARES; ++i) a_prime[i] = (p[i] << pow);
        refresh(a_prime, a_prime);
        sec_and(p, a_prime, p);
    }
    for(i=0; i < N_SHARES; ++i) a[i] = (g[i] << (1<<(W_ZERO_LOG-1))); //!!!
    sec_and(a, p, a);
    for(i=0; i < N_SHARES; ++i) g[i] ^= a[i];
    for(i=0; i < N_SHARES; ++i) z[i] = x[i]^y[i]^(g[i]<<1);
#endif
}


void sec_add128(__int128_t* x, __int128_t* y, __int128_t* z)
/// VERIFIED : does the following : 
/*  Input : 
*          x : arithmetical masking of an integer X
*          y : arithmetical masking of an integer Y
*   Output :
*          z : arithmetical masking of an integer Z such that
*                             X+Y=Z              
*/{



  masked128 p, g, a, a_prime;
  int i, j, pow;

  for(i=0; i < N_SHARES; ++i) p[i] = x[i] ^ y[i];
  sec_and128(x, y, g);
  for(j=1; j <= W_ZERO_LOG_128-1; ++j){
      pow = 1<<(j-1);
      for(i=0; i < N_SHARES; ++i) a[i] = (g[i] << pow); //!!!
      sec_and128(a, p, a);
      for(i=0; i < N_SHARES; ++i) g[i] ^= a[i];
      for(i=0; i < N_SHARES; ++i) a_prime[i] = (p[i] << pow);
      refresh128(a_prime, a_prime);
      sec_and128(p, a_prime, p);
  }
  for(i=0; i < N_SHARES; ++i) a[i] = (g[i] << (1<<(W_ZERO_LOG_128-1))); //!!!
  sec_and128(a, p, a);
  for(i=0; i < N_SHARES; ++i) g[i] ^= a[i];
  for(i=0; i < N_SHARES; ++i) z[i] = x[i]^y[i]^(g[i]<<1);

}


void sec_arith_bool_mod_p(int* a, int* a_prime)
/// VERIFIED : does the following : 
/*  Input : 
*          a : arithmetical masking of an integer A
*   Output :
*          a_prime : boolean masking of A             
*/
{

#if OPTI == 1 && MASKING_ORDER == 1
    goubin_arith_bool(a, a_prime);
#else
    convert_A_B(a, a_prime, N_SHARES);
#endif
    for(int i=0; i < N_SHARES; ++i) a_prime[i] = mod_q(a_prime[i]);

}

void sec_bool_arith(int* x_bool, int* x_arith){

#if OPTI == 1 && MASKING_ORDER == 1
    goubin_bool_arith(x_bool, x_arith);
#else
    HO_bool_arith(x_bool, x_arith, N_SHARES);
#endif    

}



int full_xor(int* x)
/// VERIFIED : does the following : 
/*  Input : 
*          x : boolean masking of an integer X
*   Output :
*          res : unmasked value X            
*/
{
    masked x_prime;
    int i,res;
    full_refresh(x, x_prime);
    res = x_prime[0];
    for(i=1; i < N_SHARES; ++i) res ^= x_prime[i];
    return res; 
}


void full_add(masked_poly m, poly res)
/* This function is the poly version of full_add           
*/
{
    int i,j;
    masked temp;
    for(i=0; i < PARAM_N; i++){
       for(j=0; j < N_SHARES; j++){temp[j]=m[j][i];} 
       res[i] = full_add_coef(temp);
   }
}

void full_add_small(masked_poly m, uint16_t* res)
/* This function is the poly version of full_add for poly with small coefs         
*/
{
    int i,j;
    masked temp;
    for(i=0; i < PARAM_N; i++){
       for(j=0; j < N_SHARES; j++){temp[j]=m[j][i];} 
       res[i] = (uint16_t)full_add_coef(temp);
   }
}

int full_add_coef(int* coef)
/// VERIFIED : does the following : 
/*  Input : 
*          masked : arithmetical masking of an integer M
*   Output :
*          res : unmasked value M            
*/
{   int j;
    masked temp;
    full_refresh_arith(coef,temp);
    int res = 0;
    for(j=0; j < N_SHARES; ++j){
        res = mod_q(res+ temp[j]);
    }  
    return res;  
}       




// http://xoshiro.di.unimi.it/xoshiro128starstar.c

/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */



/* This is xoshiro128** 1.0, our 32-bit all-purpose, rock-solid generator. It
   has excellent (sub-ns) speed, a state size (128 bits) that is large
   enough for mild parallelism, and it passes all tests we are aware of.

   For generating just single-precision (i.e., 32-bit) floating-point
   numbers, xoshiro128+ is even faster.

   The state must be seeded so that it is not everywhere zero. */


static inline uint32_t rotl(const uint32_t x, int k) {
	return (x << k) | (x >> (32 - k));
}


static uint32_t s[4];


void seed_xoshiro(void){
    srand(time(NULL));
    s[0] = rand();
    s[1] = rand();
    s[2] = rand();
    s[3] = rand();
  
}

uint32_t xoshiro_next(void) {
	const uint32_t result_starstar = rotl(s[0] * 5, 7) * 9;

	const uint32_t t = s[1] << 9;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;

	s[3] = rotl(s[3], 11);

	return result_starstar;
}


