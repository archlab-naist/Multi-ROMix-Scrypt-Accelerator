// cd /home/hork/cuda-workspace/CudaSHA256/Debug/files
// time ~/Dropbox/FIIT/APS/Projekt/CpuSHA256/a.out -f ../file-list
// time ../CudaSHA256 -f ../file-list


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cuda_runtime.h>
#include <memory.h>
#include <iostream>

#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include "sha256.h"

#define N 10
#define M 100
#define MAXLOOP M/N
//#define N 6


#define checkCudaErrors(x) \
{ \
    cudaGetLastError(); \
    x; \
    cudaError_t err = cudaGetLastError(); \
    if (err != cudaSuccess) \
        printf("GPU: cudaError %d (%s)\n", err, cudaGetErrorString(err)); \
}

// datatypes -----------------------------------------------------------------------
#ifndef DATATYPES
#define DATATYPES
// Data types

typedef unsigned char BYTE; // 8-bit byte
typedef unsigned int  WORD; // 32-bit word
#endif

// sha256 ----------------------------------------------------------------------------------------

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

static const WORD k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, \
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, \
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, \
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, \
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, \
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, \
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, \
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
 
 // Create init state for SHA-256
 void sha256_init(SHA256_CTX *ctx)
 {
     ctx->datalen = 0;
     ctx->bitlen = 0;
     ctx->state[0] = h0;
     ctx->state[1] = h1;
     ctx->state[2] = h2;
     ctx->state[3] = h3;
     ctx->state[4] = h4;
     ctx->state[5] = h5;
     ctx->state[6] = h6;
     ctx->state[7] = h7;
 }
 
 
 void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
 {
 // m is W in hardware design
   WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
 // Calculate the first 16 m elements.
   for (i = 0, j = 0; i < 16; ++i, j += 4)
     m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
 // Calculate the remain elements.
   for ( ; i < 64; ++i)
     m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
 // update the new value of state after each block
   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];
 // process 64 rounds
   for (i = 0; i < 64; ++i) {
     t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
     t2 = EP0(a) + MAJ(a,b,c);
     h = g;
     g = f;
     f = e;
     e = d + t1;
     d = c;
     c = b;
     b = a;
     a = t1 + t2;
   }
 
   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
 }
 // the total length of the message has to be specified
 void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
 {
     WORD i;
 
     for (i = 0; i < len; ++i){
         ctx->data[ctx->datalen] = data[i];      // Pad data (message) for each 512-block in --> transform
         ctx->datalen++;
         // after browse for 64 bytes (512-bit block) -> transform the block.
         if(ctx->datalen == 64){
             sha256_transform(ctx, ctx->data);
             ctx->bitlen += 512; // increase the bit length by 512
             ctx->datalen = 0;
         }
     }
 }
 // this function processes for the last block -> after all real data is browsed 
 void sha256_final(SHA256_CTX *ctx, WORD *hash){
     WORD i;
 // padding is processed from here
     i = ctx->datalen;
     if (ctx->datalen < 56){
         // add byte 0x80 at the first if the datalength is lower than 56
         ctx->data[i++] = 0x80;
         // pad the zero bytes until the byte 56th
         while (i<56)
         {
             ctx->data[i++]=0x00;
         }
     }
     else{
         // add byte at the first
         ctx->data[i++]=0x80;
         // pad zero bytes until the last block
         while (i<64){
             ctx->data[i++]=0x00;
         }
         // transform this block --> it's not the last block
         sha256_transform(ctx, ctx->data);
         // set 56 zero bytes from last_block[0:55]
         memset(ctx->data, 0, 56);
     }
 
     // Append to the padding the total message's length in bits and transform.
     ctx->bitlen += ctx->datalen * 8;
     ctx->data[63] = ctx->bitlen;
     ctx->data[62] = ctx->bitlen >> 8;
     ctx->data[61] = ctx->bitlen >> 16;
     ctx->data[60] = ctx->bitlen >> 24;
     ctx->data[59] = ctx->bitlen >> 32;
     ctx->data[58] = ctx->bitlen >> 40;
     ctx->data[57] = ctx->bitlen >> 48;
     ctx->data[56] = ctx->bitlen >> 56;
 // end padding
     sha256_transform(ctx, ctx->data);
 
     // Since this implementation uses little endian byte ordering and SHA uses big endian,
     // reverse all the bytes when copying the final state to the output hash.
 
 
         hash[0] = ctx->state[0];
         hash[1] = ctx->state[1];
         hash[2] = ctx->state[2];
         hash[3] = ctx->state[3];
         hash[4] = ctx->state[4];
         hash[5] = ctx->state[5];
         hash[6] = ctx->state[6];
         hash[7] = ctx->state[7]; 
  
 }
 
 char * sha256(SHA256_CTX *ctx, char hex_str_in[], unsigned long hex_str_len){
     
     unsigned long datalen = hex_str_len/2;
     BYTE *data=new BYTE[datalen]();
     // WORD hash_w[8]; //--> true
     // WORD *hash_w = (WORD*)malloc(sizeof(WORD)*8); //--> true
     WORD *hash_w = new WORD[64](); //--> false
     static char *out = new char[64]();
   
     hex_string_to_bytes(hex_str_in, hex_str_len, data);
     sha256_init(ctx);
 
     sha256_update(ctx, data, datalen);
 
     sha256_final(ctx,hash_w);
     words_to_hex_string(hash_w, 8, out, 64);
     return out;
 }
 
 void sha256_w(SHA256_CTX *ctx, char hex_str_in[], unsigned long hex_str_len, WORD *hash_w){
     
     unsigned long datalen = hex_str_len/2;
     BYTE *data=new BYTE[datalen]();
   
     hex_string_to_bytes(hex_str_in, hex_str_len, data);
     sha256_init(ctx);
  
     sha256_update(ctx, data, datalen);
 
     sha256_final(ctx, hash_w);
 }
 
 void sha256_in_bytes(SHA256_CTX *ctx, BYTE *bytes_in, unsigned long bytes_in_len, WORD *hash_w){
     sha256_init(ctx);
  
     sha256_update(ctx, bytes_in, bytes_in_len);
 
     sha256_final(ctx, hash_w);
 }
 
 void sha256_in_words(SHA256_CTX *ctx, WORD *words_in, unsigned long words_in_len, WORD *hash_w){
     unsigned bytes_in_len = words_in_len * 4;
     BYTE bytes_in[bytes_in_len];
 
     for (int i = 0; i<words_in_len; i++){
         bytes_in[4*i] = words_in[i] >> 24;
         bytes_in[4*i+1] = words_in[i] >> 16;
         bytes_in[4*i+2] = words_in[i] >> 8;
         bytes_in[4*i+3] = words_in[i];
     }
     
     sha256_init(ctx);
  
     sha256_update(ctx, bytes_in, bytes_in_len);
 
     sha256_final(ctx, hash_w);
 }


 // utils ------------------------------------------------------------------------------------------

 #ifndef UTILS
#define UTILS
#include "datatypes.h"
#include <iostream>
#include <algorithm>
#include <stddef.h>

BYTE hex_char_to_byte(char hex_char);
void hex_string_to_bytes(char hex_str_in[], unsigned long hex_str_len, BYTE bytes_out[]);
void half_byte_to_hex(BYTE half_byte_in, char hex);
void word_to_hex_eight(WORD word_in, char *hex_eight, unsigned long hex_eight_size);
void words_to_hex_string(WORD words_in[], unsigned long words_len, char hex_str[], unsigned long hex_str_len);
void hex_string_to_words(char hex_str_in[], unsigned long hex_str_len, WORD words_out[]);
void add_two_words_array_512_bit(WORD *a, WORD *b);
void print_words_inline(WORD *w, unsigned long w_len);
void print_words_multiline(WORD *w, unsigned long w_len);
void add_two_words_array_512_bit_with_carry(WORD *a, WORD *b);
void endian_cvt(WORD *w);
void endian_full(WORD *w, unsigned long w_len);
void little_endian(char *c, unsigned long w_len);
#endif

// ----------------------- Utils functions ------------------------
BYTE hex_char_to_byte(char hex_char){
    if(hex_char >= 'a' && hex_char <='f'){
        return hex_char - 'a' + 10;
    }
    else if(hex_char >='A' && hex_char <= 'F'){
        return hex_char - 'A' + 10;
    } else if (hex_char >='0' && hex_char <= '9')
    {
        return hex_char - '0';
    }
    return 0;
}
void hex_string_to_bytes(char hex_str_in[], unsigned long hex_str_len, BYTE bytes_out[]){
    for (int i = 0; i<hex_str_len-1; i+=2){
        bytes_out[i/2] = ((hex_char_to_byte(hex_str_in[i])) << 4) | (hex_char_to_byte(hex_str_in[i+1]));

    }
}

void hex_string_to_words(char hex_str_in[], unsigned long hex_str_len, WORD words_out[]){
    for (int i = 0; i<hex_str_len-1; i+=8){
        words_out[i/8] = (\
            hex_char_to_byte(hex_str_in[i])<<28|\
            (hex_char_to_byte(hex_str_in[i+1])<<24 & 0x0f000000)|\
            (hex_char_to_byte(hex_str_in[i+2])<<20 & 0x00f00000)|\
            (hex_char_to_byte(hex_str_in[i+3])<<16 & 0x000f0000)|\
            (hex_char_to_byte(hex_str_in[i+4])<<12 & 0x0000f000)|\
            (hex_char_to_byte(hex_str_in[i+5])<<8  & 0x00000f00)|\
            (hex_char_to_byte(hex_str_in[i+6])<<4  & 0x000000f0)|\
            (hex_char_to_byte(hex_str_in[i+7])     & 0x0000000f)\
        );
        // printf("%08x  %d\n", words_out[i/8], i/8);
    }
}
void half_byte_to_hex(BYTE half_byte_in, char *hex){
    BYTE half_byte_conv = half_byte_in & 0x0f;
    if(half_byte_conv<16){
        if (half_byte_conv>=10){
            *hex = 'a'+ half_byte_conv - 10;
            // printf("%c\n", *hex);
            return;
        }
        else if(half_byte_conv>=0){
            *hex = '0' + half_byte_conv;
            // printf("%c\n", *hex);
            return;
        }
    }
    printf("The half byte must be in range of [0:15]\n");
}

void word_to_hex_eight(WORD word_in, char *hex_eight, unsigned long hex_eight_size){
    if(hex_eight_size==8){
        half_byte_to_hex(word_in>>28, &hex_eight[0]);
        half_byte_to_hex(word_in>>24, &hex_eight[1]);
        half_byte_to_hex(word_in>>20, &hex_eight[2]);
        half_byte_to_hex(word_in>>16, &hex_eight[3]);
        half_byte_to_hex(word_in>>12, &hex_eight[4]);
        half_byte_to_hex(word_in>>8, &hex_eight[5]);
        half_byte_to_hex(word_in>>4, &hex_eight[6]);
        half_byte_to_hex(word_in, &hex_eight[7]);
        // printf("%c", hex_eight[0]);
        // printf("%d", word_in>>24);
        return;
    }
    printf("The hex_pair must have the length of two characters: %d\n", (int)hex_eight_size);
}

void words_to_hex_string(WORD *words_in, unsigned long words_len, char hex_str[], unsigned long hex_str_len){
    char hex_eight[8];
    if(hex_str_len == 8*words_len){
        for (int i = 0; i<words_len; ++i){
            // printf("\n w: %08x", words_in[i]);
            word_to_hex_eight(words_in[i], hex_eight, sizeof(hex_eight));
            hex_str[8*i] = hex_eight[0];
            hex_str[8*i+1] = hex_eight[1];
            hex_str[8*i+2] = hex_eight[2];
            hex_str[8*i+3] = hex_eight[3];
            hex_str[8*i+4] = hex_eight[4];
            hex_str[8*i+5] = hex_eight[5];
            hex_str[8*i+6] = hex_eight[6];
            hex_str[8*i+7] = hex_eight[7];
            // printf("%c \n", hex_eight[7]);
        }
        // printf("\n%s", hex_str);
        return;
    }
    printf("The hex_string must have the lenght of 4*bytes_len: %d\n", (int)hex_str_len);
}

void add_two_words_array_512_bit(WORD *a, WORD *b){
    
    for (int i = 15; i>=0; i--){

        a[i] += b[i];

    }
}

void add_two_words_array_512_bit_with_carry(WORD *a, WORD *b){
    WORD sum = 0;
    WORD sum1 = 0;
    
    for (int i = 15; i>=0; i--){

        sum = ((a[i]&0x0000ffff)+(b[i]&0x0000ffff)+(sum1>>16));
        sum1 = ((a[i]>>16)+(b[i]>>16)+(sum>>16));
        a[i]= (sum & 0x0000ffff) + (sum1<<16);

    }
}

void print_words_inline(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x", w[i]);
    }
    printf("\n");
}

void print_words_multiline(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x\n", w[i]);
    }
    printf("\n");
}

void endian_cvt(WORD *w){
    WORD out;

    out = (*w>>24)|((*w>>8)&0x0000ff00)|((*w<<8)&0x00ff0000)|(*w<<24);

    *w = out;
}

void endian_full(WORD *w, unsigned long w_len){
    for (int i = 0; i < w_len; i++)
    {
        endian_cvt(&w[i]);
    }
}
void little_endian(char *c, unsigned long w_len){
    char dc[w_len];

    for (int i = 0; i< w_len; i+=2){
        dc[w_len-2-i] = c[i];
        dc[w_len-1-i] = c[i+1];   
    }
    for (int i = 0; i< w_len; i++){
        c[i] = dc[i];

    }
    c[w_len] = '\0';
    
}

// scrypt --------------------------------------------------------------------------------------------------------------------------

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

WORD* hmac(SHA256_CTX *ctx, WORD *salt, unsigned long salt_len, WORD *message, unsigned long message_len){
    WORD *khash = (WORD*) malloc(sizeof(WORD)*8);
    sha256_in_words(ctx, message, message_len, khash);
    // for(int i=0;i<8; i++){
    //     printf("%08x", khash[i]);
    // }
    WORD ixor[16] = {\
        IPAD[0]^khash[0],\
        IPAD[1]^khash[1],\
        IPAD[2]^khash[2],\
        IPAD[3]^khash[3],\
        IPAD[4]^khash[4],\
        IPAD[5]^khash[5],\
        IPAD[6]^khash[6],\
        IPAD[7]^khash[7],\
        IPAD[0],\
        IPAD[1],\
        IPAD[2],\
        IPAD[3],\
        IPAD[4],\
        IPAD[5],\
        IPAD[6],\
        IPAD[7],\
    };

    WORD oxor[16] = {\
        OPAD[0]^khash[0],\
        OPAD[1]^khash[1],\
        OPAD[2]^khash[2],\
        OPAD[3]^khash[3],\
        OPAD[4]^khash[4],\
        OPAD[5]^khash[5],\
        OPAD[6]^khash[6],\
        OPAD[7]^khash[7],\
        OPAD[0],\
        OPAD[1],\
        OPAD[2],\
        OPAD[3],\
        OPAD[4],\
        OPAD[5],\
        OPAD[6],\
        OPAD[7],\
    };

    WORD in_ihash[sizeof(ixor)/sizeof(WORD)+salt_len];
    int i;
    for(i = 0; i<sizeof(ixor)/sizeof(WORD); i++){
        in_ihash[i] = ixor[i];
    }
   
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ihash[i] = salt[i-sizeof(ixor)/sizeof(WORD)];
    }

    WORD ihash[8];
    sha256_in_words(ctx, in_ihash, sizeof(in_ihash)/sizeof(WORD), ihash);

    WORD in_ohash[sizeof(oxor)/sizeof(WORD)+sizeof(ihash)/sizeof(WORD)];
    for(i = 0; i<sizeof(oxor)/sizeof(WORD); i++){
        in_ohash[i] = oxor[i];
    }
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ohash[i] = ihash[i-sizeof(oxor)/sizeof(WORD)];
    }


    static WORD ohash[8];
    sha256_in_words(ctx, in_ohash, sizeof(in_ohash)/sizeof(WORD), ohash);
    return ohash;
}

WORD* pbkdf2(SHA256_CTX *ctx, WORD *block, unsigned long block_len, int dklenP){
    int num_loop = 1024/dklenP;
    WORD salt[block_len+1];
    WORD *hmac_out;
    // int hmac_out_len = 8;
    static WORD *pbkdf2_out = new WORD[num_loop*8]();
    
    for(int i = 0; i<block_len; i++){
        salt[i]=block[i];
    }
    for (int i = 1; i <= num_loop; i++)
    {
        salt[block_len] = i;
        hmac_out = hmac(ctx, salt, block_len+1, block, block_len);
        for(int j = 0; j<8; j++){
            pbkdf2_out[(i-1)*8+j] = hmac_out[j];
        }
    }
    return pbkdf2_out;    
}

WORD* pbkdf2_2nd(SHA256_CTX *ctx, WORD *rm_out, unsigned long rm_out_len, WORD *block, unsigned long block_len, int dklenP){
    int num_loop = 1024/dklenP;
    WORD salt[rm_out_len+1];
    WORD *hmac_out;
    // int hmac_out_len = 8;
    static WORD *pbkdf2_out = new WORD[num_loop*8]();
    
    for(int i = 0; i<rm_out_len; i++){
        salt[i]=rm_out[i];
    }
    for (int i = 1; i <= num_loop; i++)
    {
        salt[rm_out_len] = i;
        hmac_out = hmac(ctx, salt, rm_out_len+1, block, block_len);
        for(int j = 0; j<8; j++){
            pbkdf2_out[(i-1)*8+j] = hmac_out[j];
        }
    }
    return pbkdf2_out; 
}
void salsa_round(WORD *x1, WORD *x2, WORD *x3, WORD *x4){
    *x1 = SALSA_MIX(*x1, *x4, *x3, 7);
    *x2 = SALSA_MIX(*x2, *x1, *x4, 9);
    *x3 = SALSA_MIX(*x3, *x2, *x1, 13);
    *x4 = SALSA_MIX(*x4, *x3, *x2, 18);
}

WORD * salsa20_8(WORD *x){
    static WORD out[16];
    for(int i = 0; i<4; i++){
        salsa_round(&x[4], &x[8], &x[12], &x[0]);
        salsa_round(&x[9], &x[13], &x[1], &x[5]);
        salsa_round(&x[14], &x[2], &x[6], &x[10]);
        salsa_round(&x[3], &x[7], &x[11], &x[15]);
        salsa_round(&x[1], &x[2], &x[3], &x[0]);
        salsa_round(&x[6], &x[7], &x[4], &x[5]);
        salsa_round(&x[11], &x[8], &x[9], &x[10]);
        salsa_round(&x[12], &x[13], &x[14], &x[15]);
    }
    for(int i=0; i<16; i++){
        out[i] = x[i];
    }
    return out;
}

WORD * blockmix(WORD *block){
    WORD x_arr[16];
    WORD x_arr_cpy[16];
    static WORD *out = new WORD[32]();
    for (int i = 0; i < 16; i++){
        x_arr[i] = block[i];
    }
    
    for (int i = 0; i<2; i++){
        for (int j = 0; j < 16; j++){
            x_arr_cpy[j] = x_arr[j] ^ block[j+16];
            x_arr[j] ^= block[j+16];
        }
        add_two_words_array_512_bit(x_arr, salsa20_8(x_arr_cpy));
        for (int j = 0; j < 16; j++){
            out[(16*i)+j] = x_arr[j]; 
        }
    }
    return out;
}

WORD * romix(WORD *block, int N){
    WORD mem[1024][32];
    static WORD *out = new WORD[32]();
    int j;
    for (int i = 0; i<N; i++){
        for (j = 0; j < 32; j++){
            mem[i][j] = block[j];
        }
        block = blockmix(block);
    }
    for (int i = 0; i<N; i++){
        j = (block[16] & 0x000003ff);
 
        for (int k = 0; k<32; k++){
            block[k] ^= mem[j][k];
        }
        block = blockmix(block);

    }
    out = block;
    return out;
}

WORD * scrypt(SHA256_CTX *ctx, WORD *block, unsigned long block_len, int dklenP1, int N, int dklenP2){
    int pbkdf2_out_len_1 = 8*(1024/dklenP1);
    int pbkdf2_out_len_2 = 8*(1024/dklenP2);
    WORD *pbkdf2_1_out = new WORD[pbkdf2_out_len_1]();
    WORD *romix_out = new WORD[32]();
    static WORD *pbkdf2_2_out = new WORD[pbkdf2_out_len_2]();
    pbkdf2_1_out = pbkdf2(ctx, block, block_len, dklenP1);
  
    endian_full(pbkdf2_1_out, pbkdf2_out_len_1);
    romix_out = romix(pbkdf2_1_out, N);
    endian_full(romix_out, 32);
    pbkdf2_2_out = pbkdf2_2nd(ctx, romix_out, 32, block, block_len, dklenP2);
    return pbkdf2_2_out;
}

__device__ void scrypt_cuda(SHA256_CTX *ctx, WORD block[], unsigned long block_len, int dklenP1, int N, int dklenP2, WORD hash_out[])
{
    hash_out = scrypt(ctx, block, block_len, dklenP1, N, dklenP2);
}

__global__ void scrypt_top_cuda(uint32_t max_loop) {

    uint32_t index  = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t stride = blockDim.x * gridDim.x;
    uint32_t j;
    for (j = index; j < N; j += stride){
        SHA256_CTX *ctx = new SHA256_CTX();
        char ver[]="20000000";
        char prev_block[]="48f4bdc6cbabf6e59d5714adc7caa1af293bc49c75d447c2fdc1843694d1ef56";
        char mrkl_root[]="f03a2314e267c0e67627a51aa8c7bcdd99a2d173deec41ab96945eb4c7e43dee";
        char time[9];
        char bits[9];
        little_endian(ver, sizeof(ver) - 1);
        little_endian(prev_block, sizeof(prev_block) - 1);
        little_endian(mrkl_root, sizeof(mrkl_root) - 1);
        
        // Get time

        struct tm t;
        time_t t_of_day;

        t.tm_year = 2019-1900;  // Year - 1900
        t.tm_mon = 3-1;           // Month, where 1 = jan
        t.tm_mday = 13;          // Day of the month
        t.tm_hour = 7+9;
        t.tm_min = 51;
        t.tm_sec = 51;
        t.tm_isdst = -1;        // Is DST on? 1 = yes, 0 = no, -1 = unknown
        t_of_day = mktime(&t);
        
        WORD *wtime = new WORD(t_of_day);
        endian_cvt(wtime);
        word_to_hex_eight(*wtime, time, 8);

        word_to_hex_eight(436330391, bits, 8); // bits -- input
        little_endian(bits, 8);
        char test_scrypt_in[153];


        
        int in_index = 0;
        WORD i;
        for( i = 0; i < sizeof(ver)-1; i++){
            test_scrypt_in[i]=ver[i];
        }
        in_index += sizeof(ver)-1;
        for( i = 0; i < sizeof(prev_block); i++){
            test_scrypt_in[in_index+i] = prev_block[i];
        }
        in_index += sizeof(prev_block)-1;
        for( i = 0; i < sizeof(mrkl_root); i++){
            test_scrypt_in[in_index+i] = mrkl_root[i];
        }
        in_index += sizeof(mrkl_root)-1;
        for( i = 0; i < sizeof(time); i++){
            test_scrypt_in[in_index+i] = time[i];
        }
        in_index += sizeof(time)-1;
        for( i = 0; i < sizeof(bits); i++){
            test_scrypt_in[in_index+i] = bits[i];
        }


        WORD *test_scrypt_out_w = new WORD[8]();
        char *test_scrypt_out = new char[32*8](); 
        WORD test_scrypt_in_w[20];

        for (i = j*max_loop; i<(j+1)*max_loop; i++){
            hex_string_to_words(test_scrypt_in, sizeof(test_scrypt_in), test_scrypt_in_w);
            test_scrypt_in_w[19] = i;
            endian_cvt(&test_scrypt_in_w[19]);
            scrypt_cuda(ctx, test_scrypt_in_w, 20, 256, 1024, 1024, test_scrypt_out_w);
            if(i==(index+1)*max_loop-1){
                printf("\nThread id: %d, nonce: %d\n", index, i);
            }
        }
    }

}


int main(void)
{

    
	int GPU_N;
	checkCudaErrors(cudaGetDeviceCount(&GPU_N));
	printf("CUDA-capable device count: %d\n", GPU_N);
	checkCudaErrors(cudaSetDevice(GPU_N-1));




    uint32_t blockSize = 256;
    uint32_t numBlocks = (N + blockSize - 1) / blockSize;
    // uint32_t *max_loop_cpu = (uint32_t *)malloc(sizeof(uint32_t));
    // *max_loop_cpu = M;
	// checkCudaErrors(cudaMallocManaged(&max_loop_gpu, sizeof(uint32_t)));
    // cudaMemcpy(max_loop_gpu, max_loop_cpu, cudaMemcpyHostToDevice);

	
    scrypt_top_cuda <<<numBlocks, blockSize>>> (MAXLOOP);

	cudaDeviceReset();
	
	return 0;
}	
	
