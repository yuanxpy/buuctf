#include<stdio.h>
#include "defs.h"
#include <math.h>

int main(){

    unsigned int a1 = -1;
    unsigned int a2 = 8;

    long double v2; // fst7
    unsigned int v4; // [esp+70h] [ebp+8h]

    v4 = (__int64)pow((double)a1, 0.9);
    v2 = pow((double)a2, 9.800000000000001);
    printf(
           "flag: %x%x%x%x%x%x%x%x\n",
           (unsigned __int16)v4,
           HIWORD(v4),
           (unsigned __int16)(__int64)v2,
           (unsigned int)(__int64)v2 >> 16,
           (unsigned int)(__int64)v2 >> 16,
           (unsigned __int16)(__int64)v2,
           HIWORD(v4),
           (unsigned __int16)v4);
}