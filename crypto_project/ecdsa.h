// ----- ecdsa.h -----
#ifndef ECDSA_H
#define ECDSA_H

#include <stdbool.h>
#include <stddef.h>
#define EC_P  233      // Prime field modulus 
#define EC_A  1        // Curve coefficient 'a' 
#define EC_B  44       // Curve coefficient 'b' 
#define EC_N  17       // Subgroup order 
#define EC_GX 67       // Generator x-coordinate 
#define EC_GY 184      // Generator y-coordinate

typedef struct { int x, y; bool infinity; } ec_point;
typedef struct { int private_key; ec_point public_key; } ecdsa_keypair;
typedef struct { int r, s; } ecdsa_signature;

int  mod(int a, int m);
int  mod_inv(int a, int m);
void ec_init_generator(ec_point* G);
void ec_add(ec_point* r, const ec_point* p, const ec_point* q);
void ec_scalar_mul(ec_point* r, const ec_point* p, int k);
int  hash_message(const unsigned char* m, size_t n);

void ecdsa_keygen(ecdsa_keypair* kp);
void ecdsa_sign(const ecdsa_keypair* kp,
    const unsigned char* m,
    size_t n,
    ecdsa_signature* s);
bool ecdsa_verify(const ec_point* Q,
    const unsigned char* m,
    size_t n,
    const ecdsa_signature* s);

#endif // ECDSA_H