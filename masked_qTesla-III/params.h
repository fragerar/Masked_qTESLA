/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: qTESLA parameters
**************************************************************************************/

#ifndef PARAMS_H
#define PARAMS_H

#define PARAM_N 1024
#define PARAM_N_LOG 10
#define PARAM_SIGMA 10.2
#define PARAM_Q 8388608
#define PARAM_Q_LOG 24
#define PARAM_QINV 4034936831
#define PARAM_BARR_MULT 511
#define PARAM_BARR_DIV 32
#define PARAM_B 2097151
#define PARAM_B_BITS 21
#define PARAM_S_BITS 9
#define PARAM_K 1
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 48
#define PARAM_D 22	
#define PARAM_GEN_A 38
#define PARAM_KEYGEN_BOUND_E 1147 
#define PARAM_E PARAM_KEYGEN_BOUND_E
#define PARAM_KEYGEN_BOUND_S 1233
#define PARAM_S PARAM_KEYGEN_BOUND_S
#define PARAM_R2_INVN 237839
#define PARAM_R 15873
#define SHAKE shake256
#define cSHAKE cshake256_simple
#define SHAKE_RATE SHAKE256_RATE


#define rand_uint32() xoshiro_next()
//#define rand_uint32() 0





#ifndef NRUNS
  #define NRUNS 1000
#endif
#ifndef NTESTS
  #define NTESTS 1000
#endif


#define OPTI 1
#ifndef MASKING_ORDER
	#define MASKING_ORDER 2
#endif
#define N_SHARES MASKING_ORDER+1
#define EXACT_Q_LOG 23
#define W_ZERO 21
#define W_ZERO_LOG 5
#define SECRET_SIZE 4
#define BS_W 32
#define KARATSUBOUND 32

#define COUNT


#endif
