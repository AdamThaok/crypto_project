
// ----- mceliece.c -----
#include "mceliece.h"
#include <stdlib.h>

static void generate_goppa_code(binary_matrix* g) {
    for (int i = 0; i < MC_K; i++) {
        for (int j = 0; j < MC_N; j++) {
            g->data[i][j] = (j < MC_K) ? (i == j) : (rand() & 1);
        }
    }
}

void mceliece_keygen(mceliece_keypair* kp) {
    /* generate the base Goppa code */
    generate_goppa_code(&kp->g_original);

    /* random scrambler */
    matrix_random(&kp->s);

    /* random permutation */
    matrix_permutation(&kp->p);

    /* temp = g_original * p */
    binary_matrix temp;
    for (int i = 0; i < MC_N; i++) {
        for (int j = 0; j < MC_N; j++) {
            temp.data[i][j] = 0;
            for (int k = 0; k < MC_N; k++) {
                temp.data[i][j] ^= kp->g_original.data[i][k] & kp->p.data[k][j];
            }
        }
    }

    /* kp->g = s * temp */
    for (int i = 0; i < MC_N; i++) {
        for (int j = 0; j < MC_N; j++) {
            kp->g.data[i][j] = 0;
            for (int k = 0; k < MC_N; k++) {
                kp->g.data[i][j] ^= kp->s.data[i][k] & temp.data[k][j];
            }
        }
    }
}

void mceliece_encrypt(const binary_matrix* pub,
    const binary_vector* msg,
    binary_vector* ct)
{
    vector_matrix_mul(ct, msg, pub);
    for (int e = 0; e < MC_T; e++) {
        int pos = rand() % MC_N;
        ct->data[pos] ^= 1;
    }
}
