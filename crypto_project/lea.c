// ----- lea.c -----
#include "lea.h"
#include <string.h>

static const uint32_t DELTA[8] = {
    0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,
    0x715ea49e,0xc785da0a,0xe04ef22a,0xe5c40957
};

uint32_t rol(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }
uint32_t ror(uint32_t v, int s) { return (v >> s) | (v << (32 - s)); }

void lea_set_key(LEA_KEY* key, const unsigned char* user_key, int key_len) {
    uint32_t t[4];
    for (int i = 0; i < 4; i++)
        t[i] = ((uint32_t)user_key[4 * i]) |
        ((uint32_t)user_key[4 * i + 1] << 8) |
        ((uint32_t)user_key[4 * i + 2] << 16) |
        ((uint32_t)user_key[4 * i + 3] << 24);

    key->rounds = LEA_ROUND_COUNT;
    for (int i = 0; i < key->rounds; i++) {
        t[0] = rol(t[0] + rol(DELTA[i & 3], i), 1);
        t[1] = rol(t[1] + rol(DELTA[i & 3], i + 1), 3);
        t[2] = rol(t[2] + rol(DELTA[i & 3], i + 2), 6);
        t[3] = rol(t[3] + rol(DELTA[i & 3], i + 3), 11);
        key->rk[i][0] = t[0];
        key->rk[i][1] = t[1];
        key->rk[i][2] = t[2];
        key->rk[i][3] = t[3];
        key->rk[i][4] = t[1];
        key->rk[i][5] = t[3];
    }
}

void lea_encrypt_block(const LEA_KEY* key, const unsigned char* pt, unsigned char* ct) {
    uint32_t x[4];
    for (int i = 0; i < 4; i++)
        x[i] = ((uint32_t)pt[4 * i]) |
        ((uint32_t)pt[4 * i + 1] << 8) |
        ((uint32_t)pt[4 * i + 2] << 16) |
        ((uint32_t)pt[4 * i + 3] << 24);

    for (int i = 0; i < key->rounds; i++) {
        x[0] = rol((x[0] ^ key->rk[i][0]) + (x[1] ^ key->rk[i][1]), 9);
        x[1] = ror((x[1] ^ key->rk[i][2]) + (x[2] ^ key->rk[i][3]), 5);
        x[2] = ror((x[2] ^ key->rk[i][4]) + (x[3] ^ key->rk[i][5]), 3);
        x[3] = rol(x[0] ^ x[1] ^ x[2], 1);
        if (i < key->rounds - 1) {
            uint32_t tmp = x[0];
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = tmp;
        }
    }

    for (int i = 0; i < 4; i++) {
        ct[4 * i] = (unsigned char)x[i];
        ct[4 * i + 1] = (unsigned char)(x[i] >> 8);
        ct[4 * i + 2] = (unsigned char)(x[i] >> 16);
        ct[4 * i + 3] = (unsigned char)(x[i] >> 24);
    }
}

void lea_ofb_encrypt(const LEA_KEY* key,
    const unsigned char iv[LEA_BLOCK_SIZE],
    const unsigned char* in,
    unsigned char* out,
    size_t len)
{
    unsigned char ofb[LEA_BLOCK_SIZE], ks[LEA_BLOCK_SIZE];
    memcpy(ofb, iv, LEA_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += LEA_BLOCK_SIZE) {
        lea_encrypt_block(key, ofb, ks);
        size_t chunk = (len - i < LEA_BLOCK_SIZE ? len - i : LEA_BLOCK_SIZE);
        for (size_t j = 0; j < chunk; j++)
            out[i + j] = in[i + j] ^ ks[j];
        memcpy(ofb, ks, LEA_BLOCK_SIZE);
    }
}
