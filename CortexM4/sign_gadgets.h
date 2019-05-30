#ifndef SIGN_GADGETS_H
#define SIGN_GADGETS_H

#include "poly.h"



void DG(masked_poly y, int k, const int BITSIZE);
void RG(int k_val, int* a, const int BITSIZE);

void abs_val(int* x, int* abs_x, int SB_POSITION);

unsigned char masked_rounding(int* a);

int masked_RS(int* a);
int full_RS(masked_poly p);

int masked_well_rounded(int* a);
int full_WR(masked_poly p);

#endif
