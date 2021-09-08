#ifndef PBKDF2
#define PBKDF2
#include <iostream>
#include "sha256.h"
#define ipad_elm 0x36363636
#define opad_elm 0x5c5c5c5c
#define SUM(a,b) (a+b) & 0xffffffff

// #define SALSA_MIX(destination ,a1, a2, b) (destination ^ (((SUM(a1,a2) << b) & 0xffffffff) | ((SUM(a1,a2) >> (32-b))&0xffffffff)))
#define SALSA_MIX(destination ,a1, a2, b) (destination ^ (ROTLEFT(SUM(a1,a2),b)))



const WORD IPAD[8] = {ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm}; // 256-bit 363636...36   
const WORD OPAD[8] = {opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm}; // 256-bit 5c5c5c...5c

// Function in scrypt
WORD* hmac(SHA256_CTX *ctx, WORD *salt, unsigned long salt_len, WORD *message, unsigned long message_len);
WORD* pbkdf2(SHA256_CTX *ctx, WORD *block, unsigned long block_len, int dklenP);
WORD* pbkdf2_2nd(SHA256_CTX *ctx, WORD *rm_out, unsigned long rm_out_len, WORD *block, unsigned long block_len, int dklenP);
void salsa_round(WORD *x1, WORD *x2, WORD *x3, WORD *x4);
WORD * salsa20_8(WORD *x);
WORD * blockmix(WORD *block);
WORD * romix(WORD *block, int N);
WORD * scrypt(SHA256_CTX *ctx, WORD *block, unsigned long block_len, int dklenP1, int N, int dklenP2);
#endif