/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: qTESLA parameters
**************************************************************************************/

#ifndef PARAMS_H
#define PARAMS_H

#define PARAM_N 512
#define PARAM_N_LOG 9
#define PARAM_SIGMA 22.93
#define PARAM_Q 4194304
#define PARAM_Q_LOG 23 // actually bigger than log Q for packing compatibility
#define PARAM_QINV 3098553343
#define PARAM_BARR_MULT 1021
#define PARAM_BARR_DIV 32
#define PARAM_B 1048575
#define PARAM_B_BITS 20
#define PARAM_S_BITS 9
#define PARAM_K 1
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 30
#define PARAM_D 21
#define PARAM_GEN_A 19	
#define PARAM_KEYGEN_BOUND_E 1586 
#define PARAM_E PARAM_KEYGEN_BOUND_E
#define PARAM_KEYGEN_BOUND_S 1586
#define PARAM_S PARAM_KEYGEN_BOUND_S
#define PARAM_R2_INVN 113307
#define PARAM_R 1081347
#define SHAKE shake128
#define cSHAKE cshake128_simple
#define SHAKE_RATE SHAKE128_RATE


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
	#define MASKING_ORDER 1
#endif
#define N_SHARES MASKING_ORDER+1
#define EXACT_Q_LOG 22
#define W_ZERO 21
#define W_ZERO_LOG 5
#define SECRET_SIZE 4
#define BS_W 32
#define KARATSUBOUND 32

//#define COUNT


#endif
