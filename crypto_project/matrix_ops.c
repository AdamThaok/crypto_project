
// ----- matrix_ops.c -----
#include "matrix_ops.h"
#include <stdlib.h>

void matrix_random(binary_matrix* m) {
    for (int i = 0; i < MC_N; i++)
        for (int j = 0; j < MC_N; j++)
            m->data[i][j] = rand() & 1;
}

void matrix_identity(binary_matrix* m) {
    for (int i = 0; i < MC_N; i++)
        for (int j = 0; j < MC_N; j++)
            m->data[i][j] = (i == j);
}

void matrix_permutation(binary_matrix* m) {
    matrix_identity(m);
    for (int i = MC_N - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        for (int k = 0; k < MC_N; k++) {
            uint8_t t = m->data[i][k];
            m->data[i][k] = m->data[j][k];
            m->data[j][k] = t;
        }
    }
}

void vector_matrix_mul(binary_vector* r,
    const binary_vector* v,
    const binary_matrix* m)
{
    for (int i = 0; i < MC_N; i++) {
        r->data[i] = 0;
        for (int j = 0; j < MC_N; j++)
            r->data[i] ^= v->data[j] & m->data[j][i];
    }
}
