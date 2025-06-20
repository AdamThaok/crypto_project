// ----- lea.h -----
#ifndef LEA_H
#define LEA_H

#include <stddef.h>
#include <stdint.h>

#define LEA_BLOCK_SIZE 16
#define LEA_ROUND_COUNT 24

typedef struct {
    uint32_t rk[LEA_ROUND_COUNT][6];
    int rounds;
} LEA_KEY;

uint32_t rol(uint32_t v, int s);
uint32_t ror(uint32_t v, int s);

void lea_set_key(LEA_KEY* key, const unsigned char* user_key, int key_len);
void lea_encrypt_block(const LEA_KEY* key, const unsigned char* pt, unsigned char* ct);
void lea_ofb_encrypt(const LEA_KEY* key,
    const unsigned char iv[LEA_BLOCK_SIZE],
    const unsigned char* in,
    unsigned char* out,
    size_t len);
#define lea_ofb_decrypt lea_ofb_encrypt

#endif // LEA_H
#pragma once
