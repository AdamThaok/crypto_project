// ----- matrix_ops.h -----
#ifndef MATRIX_OPS_H
#define MATRIX_OPS_H

#include <stdint.h>

#define MC_N 32

typedef struct { uint8_t data[MC_N]; } binary_vector;
typedef struct { uint8_t data[MC_N][MC_N]; } binary_matrix;

/* generic matrix/vector utilities */
void matrix_random(binary_matrix* m);
void matrix_identity(binary_matrix* m);
void matrix_permutation(binary_matrix* m);
void vector_matrix_mul(binary_vector* r,
    const binary_vector* v,
    const binary_matrix* m);

#endif // MATRIX_OPS_H

