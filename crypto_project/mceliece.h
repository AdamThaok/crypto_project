// ----- mceliece.h -----
#ifndef MCELIECE_H
#define MCELIECE_H

#include "matrix_ops.h"

#define MC_K 16
#define MC_T 3

typedef struct {
    binary_matrix g, s, p, g_original;
} mceliece_keypair;

void mceliece_keygen(mceliece_keypair* kp);
void mceliece_encrypt(const binary_matrix* pub,
    const binary_vector* msg,
    binary_vector* ct);

#endif // MCELIECE_H

