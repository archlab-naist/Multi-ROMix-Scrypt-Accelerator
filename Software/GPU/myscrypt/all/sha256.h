
#ifndef SHA256_H
# define SHA256_H
#include <iostream>
#include <algorithm>
#include <stddef.h>
#include "utils.h"
#include "datatypes.h"

using std::string;

#define h0 0x6a09e667
#define h1 0xbb67ae85
#define h2 0x3c6ef372
#define h3 0xa54ff53a
#define h4 0x510e527f
#define h5 0x9b05688c
#define h6 0x1f83d9ab
#define h7 0x5be0cd19


// Macros
#define SHA256_BLOCK_SIZE 32 

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ (ROTRIGHT(x,22)))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ (ROTRIGHT(x,25)))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))


typedef struct SHA256_CTX
{
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;

// Functions
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, WORD hash[]);
char * sha256(SHA256_CTX *ctx, char hex_str_in[], unsigned long hex_str_len);
void sha256_w(SHA256_CTX *ctx, char hex_str_in[], unsigned long hex_str_len, WORD *hash_w);
void sha256_in_bytes(SHA256_CTX *ctx, BYTE *bytes_in, unsigned long bytes_in_len, WORD *hash_w);
void sha256_in_words(SHA256_CTX *ctx, WORD *words_in, unsigned long words_in_len, WORD *hash_w);
#endif