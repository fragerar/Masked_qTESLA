#ifndef BASE_GADGETS_H
#define BASE_GADGETS_H

#include "poly.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

typedef int masked[MASKING_ORDER+1];

void full_add(masked_poly, poly res);
void full_add_small(masked_poly, uint16_t* res);
int full_add_coef(int* masked);
int full_xor(int* x);
void refresh(int* x, int* res);
void refresh_vs(int* x, int* res, const int N);
void refresh_masks_n(int* x, int* y, const int N);
void expand(int* x, int* out, const int N);
void full_refresh(int* x, int* res);
void full_refresh_arith(int* x, int* res);
void sec_and(int* x, int* y, int* res);
void sec_and_vs(int* x, int* y, int* res, const int N);
void sec_add(int* x, int* y, int* z);
void sec_add_vs(int* x, int* y, int* z, const int N);
void sec_and_const(int* x, int* y, int* res);
void sec_add_const(int* x, int* y, int* z);

void sec_arith_bool_mod_p(int* a, int* a_prime);
void sec_bool_arith(int* x_bool, int* x_arith);
void convert_A_B(int* arith_x, int* bool_x, const int N);

void goubin_bool_arith(int* bool_x, int* arith_x);
void goubin_arith_bool(int* arith_x, int* bool_x);
void order_1_add(int* x, int* y, int* z);
int order_1_AND(int x, int y, int s, int t, int u);
void HO_bool_arith(int* bool_x, int* arith_x, const int N);
void seed_xoshiro(void);
uint32_t xoshiro_next(void);


#endif
