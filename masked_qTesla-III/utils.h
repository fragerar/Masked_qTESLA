#ifndef UTILS_H
#define UTILS_H

#include "params.h"
#include "poly.h"
#include <stdio.h>

int mod_q(int a);
void print_bytes(unsigned char* b, int len);
void print_bits(int x);
void print_shares(int* x);
void print_shares_vs(int* x, const int N);
void print_shares_bits(int* x);
void print_shares_bits_vs(int* x, const int N);
void print_full_bits(int x);
void print_full_shares_bits(int* x);

void print_masked_poly(masked_poly p);
void print_poly_py(poly p);
void print_small_poly(int16_t* p);
void print_poly(poly p);
void print_small_masked_poly(masked_small_poly p);
void print_poly_f(poly p);

#endif
