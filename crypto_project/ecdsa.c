// ----- ecdsa.c -----
#include "ecdsa.h"

static int mod(int a, int m) {
    int r = a % m;
    return r < 0 ? r + m : r;
}

static int mod_inv(int a, int m) {
    int t = 0, newt = 1, r = m, newr = mod(a, m);
    while (newr) {
        int q = r / newr;
        int tmp = newt; newt = t - q * newt; t = tmp;
        tmp = newr; newr = r - q * newr; r = tmp;
    }
    return (r > 1 ? -1 : (t < 0 ? t + m : t));
}

void ec_init_generator(ec_point* G) {
    G->x = EC_GX;
    G->y = EC_GY;
    G->infinity = false;
}

void ec_add(ec_point* r, const ec_point* p, const ec_point* q) {
    if (p->infinity) { *r = *q; return; }
    if (q->infinity) { *r = *p; return; }
    if (p->x == q->x && p->y == (EC_P - q->y) % EC_P) {
        r->infinity = true;
        return;
    }

    int λ;
    if (p->x == q->x && p->y == q->y) {
        λ = mod((3 * p->x * p->x + EC_A) * mod_inv(2 * p->y, EC_P), EC_P);
    }
    else {
        λ = mod((q->y - p->y) * mod_inv(mod(q->x - p->x, EC_P), EC_P), EC_P);
    }

    r->x = mod(λ * λ - p->x - q->x, EC_P);
    r->y = mod(λ * (p->x - r->x) - p->y, EC_P);
    r->infinity = false;
}

void ec_scalar_mul(ec_point* r, const ec_point* p, int k) {
    ec_point R = { 0,0,true }, T = *p;
    while (k) {
        if (k & 1) ec_add(&R, &R, &T);
        ec_add(&T, &T, &T);
        k >>= 1;
    }
    *r = R;
}

int hash_message(const unsigned char* m, size_t n) {
    unsigned h = 0;
    for (size_t i = 0; i < n; i++)
        h = (h << 5) + h + m[i];
    return mod(h, EC_N);
}

void ecdsa_keygen(ecdsa_keypair* kp) {
    kp->private_key = (rand() % (EC_N - 1)) + 1;
    ec_point G; ec_init_generator(&G);
    ec_scalar_mul(&kp->public_key, &G, kp->private_key);
}

void ecdsa_sign(const ecdsa_keypair* kp,
    const unsigned char* m,
    size_t n,
    ecdsa_signature* s)
{
    int e = hash_message(m, n), k;
    ec_point kG;
    do {
        k = (rand() % (EC_N - 1)) + 1;
        ec_init_generator(&kG);
        ec_scalar_mul(&kG, &kG, k);
        s->r = mod(kG.x, EC_N);
    } while (s->r == 0);

    int w = mod_inv(k, EC_N);
    s->s = mod(w * (e + s->r * kp->private_key), EC_N);
    if (s->s == 0) ecdsa_sign(kp, m, n, s);
}

bool ecdsa_verify(const ec_point* Q,
    const unsigned char* m,
    size_t n,
    const ecdsa_signature* s)
{
    if (s->r <= 0 || s->r >= EC_N || s->s <= 0 || s->s >= EC_N)
        return false;

    int e = hash_message(m, n), w = mod_inv(s->s, EC_N);
    int u1 = mod(e * w, EC_N), u2 = mod(s->r * w, EC_N);
    ec_point G, p1, p2, R;
    ec_init_generator(&G);
    ec_scalar_mul(&p1, &G, u1);
    ec_scalar_mul(&p2, Q, u2);
    ec_add(&R, &p1, &p2);

    if (R.infinity) {
        return false;
    }

    return mod(R.x, EC_N) == s->r;  // Fixed comparison
}

