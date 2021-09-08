#include <stdint.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <iostream>
#include <stdio.h>
#include <algorithm>
#include <stddef.h>
// helper functions and utilities to work with CUDA
// #include <helper_functions.h>
// #include <helper_cuda.h>
#define CORRECTNONCE 235472032
#define MAXNONCE 10000000
#define NUMTHREAD 65536
#define BLOCKSIZE 256
#define STARTATNONCE CORRECTNONCE-MAXNONCE+1

// -----------------------------------------------------------------------------------------------------------------------------------
typedef unsigned char BYTE; // 8-bit byte
typedef uint32_t  WORD; // 32-bit word
// -----------------------------------------------------------------------------------------------------------------------------------
#define ipad_elm 0x36363636
#define opad_elm 0x5c5c5c5c
#define SUM(a,b) (a+b) & 0xffffffff
// -----------------------------------------------------------------------------------------------------------------------------------
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
typedef struct SHA256_CTX_W
{
    WORD data[16];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX_W;



typedef struct SCRYPT_PKG{
    SHA256_CTX_W ctx;
    WORD input[20];
    WORD output[8];
    WORD mem[1024][32];
    WORD salt[21];
    WORD hmac_out[8];
    
    WORD in_ihash[37];
    WORD in_2_ihash[49];
    WORD pbkdf2_rm_out[32];
    WORD ihash[8];
    WORD khash[8];
    WORD in_ohash[24];
    
}SCRYPT_PKG;

// -----------------------------------------------------------------------------------------------------------------------------------

#define SALSA_MIX(destination ,a1, a2, b) (destination ^ (ROTLEFT(SUM(a1,a2),b)))






#define ipad_elm 0x36363636
#define opad_elm 0x5c5c5c5c
#define SUM(a,b) (a+b) & 0xffffffff


__device__ BYTE hex_char_to_byte(char hex_char){
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

BYTE hex_char_to_byte_host(char hex_char){
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
__device__ void hex_string_to_bytes(char hex_str_in[], unsigned long hex_str_len, BYTE bytes_out[]){
    for (int i = 0; i<hex_str_len-1; i+=2){
        bytes_out[i/2] = ((hex_char_to_byte(hex_str_in[i])) << 4) | (hex_char_to_byte(hex_str_in[i+1]));

    }
}

__device__ void hex_string_to_words(char hex_str_in[], unsigned long hex_str_len, WORD words_out[]){
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

void hex_string_to_words_host(char hex_str_in[], unsigned long hex_str_len, WORD words_out[]){
    for (int i = 0; i<hex_str_len-1; i+=8){
        words_out[i/8] = (\
            hex_char_to_byte_host(hex_str_in[i])<<28|\
            (hex_char_to_byte_host(hex_str_in[i+1])<<24 & 0x0f000000)|\
            (hex_char_to_byte_host(hex_str_in[i+2])<<20 & 0x00f00000)|\
            (hex_char_to_byte_host(hex_str_in[i+3])<<16 & 0x000f0000)|\
            (hex_char_to_byte_host(hex_str_in[i+4])<<12 & 0x0000f000)|\
            (hex_char_to_byte_host(hex_str_in[i+5])<<8  & 0x00000f00)|\
            (hex_char_to_byte_host(hex_str_in[i+6])<<4  & 0x000000f0)|\
            (hex_char_to_byte_host(hex_str_in[i+7])     & 0x0000000f)\
        );
        // printf("%08x  %d\n", words_out[i/8], i/8);
    }
}
__device__ void half_byte_to_hex(BYTE half_byte_in, char *hex){
    BYTE half_byte_conv = half_byte_in & 0x0f;
    if(half_byte_conv<16){
        if (half_byte_conv>=10){
            *hex = 'a'+ half_byte_conv - 10;
            // printf("%c\n", *hex);
            return;
        }
        else{
            *hex = '0' + half_byte_conv;
            // printf("%c\n", *hex);
            return;
        }
    }
    printf("The half byte must be in range of [0:15]\n");
}

void half_byte_to_hex_host(BYTE half_byte_in, char *hex){
    BYTE half_byte_conv = half_byte_in & 0x0f;
    if(half_byte_conv<16){
        if (half_byte_conv>=10){
            *hex = 'a'+ half_byte_conv - 10;
            // printf("%c\n", *hex);
            return;
        }
        else{
            *hex = '0' + half_byte_conv;
            // printf("%c\n", *hex);
            return;
        }
    }
    printf("The half byte must be in range of [0:15]\n");
}
__device__ void word_to_hex_eight(WORD word_in, char *hex_eight, unsigned long hex_eight_size){
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

void word_to_hex_eight_host(WORD word_in, char *hex_eight, unsigned long hex_eight_size){
    if(hex_eight_size==8){
        half_byte_to_hex_host(word_in>>28, &hex_eight[0]);
        half_byte_to_hex_host(word_in>>24, &hex_eight[1]);
        half_byte_to_hex_host(word_in>>20, &hex_eight[2]);
        half_byte_to_hex_host(word_in>>16, &hex_eight[3]);
        half_byte_to_hex_host(word_in>>12, &hex_eight[4]);
        half_byte_to_hex_host(word_in>>8, &hex_eight[5]);
        half_byte_to_hex_host(word_in>>4, &hex_eight[6]);
        half_byte_to_hex_host(word_in, &hex_eight[7]);
        // printf("%c", hex_eight[0]);
        // printf("%d", word_in>>24);
        return;
    }
    printf("The hex_pair must have the length of two characters: %d\n", (int)hex_eight_size);
}

__device__ void words_to_hex_string(WORD *words_in, unsigned long words_len, char hex_str[], unsigned long hex_str_len){
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

__device__ void add_two_words_array_512_bit(WORD *a, WORD *b){
    
    for (int i = 15; i>=0; i--){

        a[i] += b[i];

    }
}

__device__ void add_two_words_array_512_bit_with_carry(WORD *a, WORD *b){
    WORD sum = 0;
    WORD sum1 = 0;
    
    for (int i = 15; i>=0; i--){

        sum = ((a[i]&0x0000ffff)+(b[i]&0x0000ffff)+(sum1>>16));
        sum1 = ((a[i]>>16)+(b[i]>>16)+(sum>>16));
        a[i]= (sum & 0x0000ffff) + (sum1<<16);

    }
}

__device__ void print_words_inline(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x", w[i]);
    }
    printf("\n");
}

void print_words_inline_host(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x", w[i]);
    }
    printf("\n");
}

void print_words_multiline_host(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x\n", w[i]);
    }
    printf("\n");
}

__device__ void print_words_multiline(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x\n", w[i]);
    }
    printf("\n");
}

__device__ void endian_cvt(WORD *w){
    WORD out;

    out = (*w>>24)|((*w>>8)&0x0000ff00)|((*w<<8)&0x00ff0000)|(*w<<24);

    *w = out;
}

__device__ void endian_full(WORD *w, unsigned long w_len){
    for (int i = 0; i < w_len; i++)
    {
        endian_cvt(&w[i]);
    }
}
void little_endian(char *c, unsigned long w_len){
    char *dc = (char*)malloc(w_len);

    for (int i = 0; i< w_len; i+=2){
        dc[w_len-2-i] = c[i];
        dc[w_len-1-i] = c[i+1];   
    }
    for (int i = 0; i< w_len; i++){
        c[i] = dc[i];

    }
    c[w_len] = '\0';
    
}

void endian_cvt_host(WORD *w){
    WORD out;

    out = (*w>>24)|((*w>>8)&0x0000ff00)|((*w<<8)&0x00ff0000)|(*w<<24);

    *w = out;
}

 
 // Create init state for SHA-256
 __device__ void sha256_init(SHA256_CTX *ctx)
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
 
  // Create init state for SHA-256
  __device__ void sha256_init_words(SHA256_CTX_W *ctx)
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
  
 __device__ void sha256_transform(SHA256_CTX *ctx, BYTE data[])
 {
    static const WORD k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, \
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, \
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, \
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, \
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, \
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, \
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, \
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
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

 __device__ void sha256_transform_words(SHA256_CTX_W *ctx, WORD data[])
 {
    static const WORD k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, \
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, \
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, \
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, \
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, \
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, \
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, \
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
 // m is W in hardware design
   WORD a, b, c, d, e, f, g, h, i, t1, t2, m[64];
 // Calculate the first 16 m elements.
   for (i = 0; i < 16; ++i)
     m[i] = data[i];
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
 __device__ void sha256_update(SHA256_CTX *ctx,  BYTE data[], size_t len)
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

 __device__ void sha256_update_words(SHA256_CTX_W *ctx, WORD data[], size_t len)
 {
     WORD i;
 
     for (i = 0; i < len; ++i){
         ctx->data[ctx->datalen] = data[i];      // Pad data (message) for each 512-block in --> transform
         ctx->datalen++;
         // after browse for 64 bytes (512-bit block) -> transform the block.
         if(ctx->datalen == 16){
             sha256_transform_words(ctx, ctx->data);
             ctx->bitlen += 512; // increase the bit length by 512
             ctx->datalen = 0;
         }
     }
 }
 // this function processes for the last block -> after all real data is browsed 
 __device__ void sha256_final(SHA256_CTX *ctx, WORD *hash){
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
 
  // this function processes for the last block -> after all real data is browsed 
  __device__ void sha256_final_words(SHA256_CTX_W *ctx, WORD *hash){
    WORD i;
// padding is processed from here
    i = ctx->datalen;
    if (ctx->datalen < 14){
        // add byte 0x80 at the first if the datalength is lower than 56
        ctx->data[i++] = 0x80000000;
        // pad the zero bytes until the byte 56th
        while (i<14)
        {
            ctx->data[i++]=0x00000000;
        }
    }
    else{
        // add bit 1 at the first
        ctx->data[i++]=0x80000000;
        // pad zero bytes until the last block
        while (i<16){
            ctx->data[i++]=0x00000000;
        }
        // transform this block --> it's not the last block
        sha256_transform_words(ctx, ctx->data);
        // set 56 zero bytes from last_block[0:55]
        ctx->data[0] =0x00000000;
        ctx->data[1] =0x00000000;
        ctx->data[2] =0x00000000;
        ctx->data[3] =0x00000000;
        ctx->data[4] =0x00000000;
        ctx->data[5] =0x00000000;
        ctx->data[6] =0x00000000;
        ctx->data[7] =0x00000000;
        ctx->data[8] =0x00000000;
        ctx->data[9] =0x00000000;
        ctx->data[10]=0x00000000;
        ctx->data[11]=0x00000000;
        ctx->data[12]=0x00000000;
        ctx->data[13]=0x00000000;
    }

    // Append to the padding the total message's length in bits and transform.
    ctx->bitlen += ctx->datalen * 32;
    ctx->data[15] = ctx->bitlen;
    ctx->data[14] = ctx->bitlen>>32;


// end padding
    sha256_transform_words(ctx, ctx->data);

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

 __device__ void sha256_in_words(SHA256_CTX_W *ctx, WORD *words_in, unsigned long words_in_len, WORD *hash_w){

    // printf("\n%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", words_in[0], words_in[1], words_in[2], words_in[3], words_in[4], words_in[5], words_in[6], words_in[7], words_in[8], words_in[9], words_in[10], words_in[11], words_in[12], words_in[13], words_in[14], words_in[15], words_in[16], words_in[17], words_in[18], words_in[19], words_in[20], words_in[21], words_in[22], words_in[23]); // true

     sha256_init_words(ctx);
     
     sha256_update_words(ctx, words_in, words_in_len);
    //  print_words_inline(ctx->state, 8);
     sha256_final_words(ctx, hash_w);
     
 }
 
 __device__ void sha256_in_words_org(SHA256_CTX *ctx, WORD *words_in, unsigned long words_in_len, WORD *hash_w){
     unsigned long bytes_in_len = words_in_len * 4;
    //  printf("%d\n", words_in_len);
    // printf("\n%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", words_in[0], words_in[1], words_in[2], words_in[3], words_in[4], words_in[5], words_in[6], words_in[7], words_in[8], words_in[9], words_in[10], words_in[11], words_in[12], words_in[13], words_in[14], words_in[15], words_in[16], words_in[17], words_in[18], words_in[19], words_in[20], words_in[21], words_in[22], words_in[23]); // true
    BYTE *bytes_in = (BYTE *)malloc((bytes_in_len)*sizeof(BYTE));
     for (int i = 0; i<words_in_len; i++){
         bytes_in[4*i] = words_in[i] >> 24;
         bytes_in[4*i+1] = words_in[i] >> 16;
         bytes_in[4*i+2] = words_in[i] >> 8;
         bytes_in[4*i+3] = words_in[i];
        //  printf("%x %x %x %x ", bytes_in[4*i], bytes_in[4*i+1], bytes_in[4*i+2], bytes_in[4*i+3]);
     }
     sha256_init(ctx);
     
     sha256_update(ctx, bytes_in, bytes_in_len);
    //  print_words_inline(ctx->state, 8);
     sha256_final(ctx, hash_w);
     
 }
 __device__ void sha256_in_words_test(SHA256_CTX_W *ctx, WORD *words_in, unsigned long words_in_len, WORD *hash_w){

   //  printf("%d\n", words_in_len);
   // printf("\n%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", words_in[0], words_in[1], words_in[2], words_in[3], words_in[4], words_in[5], words_in[6], words_in[7], words_in[8], words_in[9], words_in[10], words_in[11], words_in[12], words_in[13], words_in[14], words_in[15], words_in[16], words_in[17], words_in[18], words_in[19], words_in[20], words_in[21], words_in[22], words_in[23]); // true
   
   

    sha256_init_words(ctx);
    
    sha256_update_words(ctx, words_in, words_in_len);
   //  print_words_inline(ctx->state, 8);
    sha256_final_words(ctx, hash_w);
    
}


__device__ void hmac(SHA256_CTX_W *ctx, WORD *salt, unsigned long salt_len, WORD *message, unsigned long message_len, WORD* out_hmac){
     WORD IPAD[8] = {ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm}; // 256-bit 363636...36   
     WORD OPAD[8] = {opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm}; // 256-bit 5c5c5c...5c
    WORD *khash = (WORD*) malloc(sizeof(WORD)*8);
    // print_words_inline(message, 20); // OK
 
    sha256_in_words(ctx, message, message_len, khash);
    
    // print_words_inline(khash, 8); // OK
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
    WORD *in_ihash = (WORD*)malloc((sizeof(ixor)/sizeof(WORD)+salt_len)*sizeof(WORD));
    unsigned long in_ihash_len = sizeof(ixor)/sizeof(WORD)+salt_len;

    int i;
    for(i = 0; i<sizeof(ixor)/sizeof(WORD); i++){
        in_ihash[i] = ixor[i];
    }
   
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ihash[i] = salt[i-sizeof(ixor)/sizeof(WORD)];
    }
    
    WORD *ihash = (WORD*)malloc(8*sizeof(WORD));
    // print_words_inline(in_ihash, sizeof(ixor)/sizeof(WORD)+salt_len); // Problem
    sha256_in_words(ctx, in_ihash, in_ihash_len, ihash); // Why it's wrong
    // print_words_inline(ihash, 8); // OK
    unsigned long in_ohash_len = sizeof(oxor)/sizeof(WORD)+8;
    WORD *in_ohash = (WORD*)malloc(in_ohash_len*sizeof(WORD));  // WORD[24]

    // printf("%d\n", (in_ohash_len));
    // printf("%d\n", in_ohash_len); // 24 --> true
    for(i = 0; i<sizeof(oxor)/sizeof(WORD); i++){
        in_ohash[i] = oxor[i];
    }
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ohash[i] = ihash[i-sizeof(oxor)/sizeof(WORD)];
    }

    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x %d\n", in_ohash[0], in_ohash[1], in_ohash[2], in_ohash[3], in_ohash[4], in_ohash[5], in_ohash[6], in_ohash[7], in_ohash[8], in_ohash[9], in_ohash[10], in_ohash[11], in_ohash[12], in_ohash[13], in_ohash[14], in_ohash[15], in_ohash[16], in_ohash[17], in_ohash[18], in_ohash[19], in_ohash[20], in_ohash[21], in_ohash[22], in_ohash[23], in_ohash_len); // true

    WORD temp[] = {in_ohash[0], in_ohash[1], in_ohash[2], in_ohash[3], in_ohash[4], in_ohash[5], in_ohash[6], in_ohash[7], in_ohash[8], in_ohash[9], in_ohash[10], in_ohash[11], in_ohash[12], in_ohash[13], in_ohash[14], in_ohash[15], in_ohash[16], in_ohash[17], in_ohash[18], in_ohash[19], in_ohash[20], in_ohash[21], in_ohash[22], in_ohash[23]};
    // static WORD ohash[8];
    // printf("\n");
    sha256_in_words(ctx, temp, in_ohash_len, out_hmac);
    // print_words_inline(ohash, 8); // OK
    
    // return ohash;
}
__device__ void hmac_2(SHA256_CTX_W *ctx, WORD *salt, unsigned long salt_len, WORD *message, unsigned long message_len, WORD* out_hmac, WORD khash[8], WORD in_ihash[49], WORD ihash[8], WORD in_ohash[24]){
     WORD IPAD[8] = {ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm}; // 256-bit 363636...36   
     WORD OPAD[8] = {opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm}; // 256-bit 5c5c5c...5c

    // print_words_inline(message, 20); // OK
 
    // sha256_in_words(ctx, message, message_len, khash);
    
    // print_words_inline(khash, 8); // OK
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

    unsigned long in_ihash_len = sizeof(ixor)/sizeof(WORD)+salt_len;
    // printf("%d\n", (sizeof(ixor)/sizeof(WORD)+salt_len));
    int i;
    for(i = 0; i<sizeof(ixor)/sizeof(WORD); i++){
        in_ihash[i] = ixor[i];
    }
   
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ihash[i] = salt[i-sizeof(ixor)/sizeof(WORD)];
    }
    

    // print_words_inline(in_ihash, sizeof(ixor)/sizeof(WORD)+salt_len); // Problem
    sha256_in_words(ctx, in_ihash, in_ihash_len, ihash); // Why it's wrong
    // print_words_inline(ihash, 8); // OK
    unsigned long in_ohash_len = sizeof(oxor)/sizeof(WORD)+8;


    
    // printf("%d\n", in_ohash_len); // 24 --> true
    for(i = 0; i<sizeof(oxor)/sizeof(WORD); i++){
        in_ohash[i] = oxor[i];
    }
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ohash[i] = ihash[i-sizeof(oxor)/sizeof(WORD)];
    }

    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x %d\n", in_ohash[0], in_ohash[1], in_ohash[2], in_ohash[3], in_ohash[4], in_ohash[5], in_ohash[6], in_ohash[7], in_ohash[8], in_ohash[9], in_ohash[10], in_ohash[11], in_ohash[12], in_ohash[13], in_ohash[14], in_ohash[15], in_ohash[16], in_ohash[17], in_ohash[18], in_ohash[19], in_ohash[20], in_ohash[21], in_ohash[22], in_ohash[23], in_ohash_len); // true

    WORD temp[] = {in_ohash[0], in_ohash[1], in_ohash[2], in_ohash[3], in_ohash[4], in_ohash[5], in_ohash[6], in_ohash[7], in_ohash[8], in_ohash[9], in_ohash[10], in_ohash[11], in_ohash[12], in_ohash[13], in_ohash[14], in_ohash[15], in_ohash[16], in_ohash[17], in_ohash[18], in_ohash[19], in_ohash[20], in_ohash[21], in_ohash[22], in_ohash[23]};
    // static WORD ohash[8];
    // printf("\n");
    sha256_in_words(ctx, temp, in_ohash_len, out_hmac);
    // print_words_inline(ohash, 8); // OK
    
    // return ohash;
}

__device__ void hmac_test(SHA256_CTX_W *ctx, WORD *salt, unsigned long salt_len, WORD *message, unsigned long message_len, WORD* out_hmac, WORD khash[8], WORD in_ihash[37], WORD ihash[8], WORD in_ohash[24]){
    // WORD IPAD[8] = {ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm, ipad_elm}; // 256-bit 363636...36   
    // WORD OPAD[8] = {opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm, opad_elm}; // 256-bit 5c5c5c...5c

    // print_words_inline(message, 20); // OK
    
    sha256_in_words(ctx, message, message_len, khash);
    
    // print_words_inline(khash, 8); // OK
    // for(int i=0;i<8; i++){
    //     printf("%08x", khash[i]);
    // }
    
    WORD ixor[16] = {\
        0x36363636^khash[0],\
        0x36363636^khash[1],\
        0x36363636^khash[2],\
        0x36363636^khash[3],\
        0x36363636^khash[4],\
        0x36363636^khash[5],\
        0x36363636^khash[6],\
        0x36363636^khash[7],\
        0x36363636,\
        0x36363636,\
        0x36363636,\
        0x36363636,\
        0x36363636,\
        0x36363636,\
        0x36363636,\
        0x36363636,\
    };

    WORD oxor[16] = {\
        0x5C5C5C5C^khash[0],\
        0x5C5C5C5C^khash[1],\
        0x5C5C5C5C^khash[2],\
        0x5C5C5C5C^khash[3],\
        0x5C5C5C5C^khash[4],\
        0x5C5C5C5C^khash[5],\
        0x5C5C5C5C^khash[6],\
        0x5C5C5C5C^khash[7],\
        0x5C5C5C5C,\
        0x5C5C5C5C,\
        0x5C5C5C5C,\
        0x5C5C5C5C,\
        0x5C5C5C5C,\
        0x5C5C5C5C,\
        0x5C5C5C5C,\
        0x5C5C5C5C,\
    };
    // print_words_inline(IPAD, 8);
    // print_words_inline(OPAD, 8);
    unsigned long in_ihash_len = 37;
    int i;
    
    for(i = 0; i<sizeof(ixor)/sizeof(WORD); i++){
        in_ihash[i] = ixor[i];
    }
   
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ihash[i] = salt[i-sizeof(ixor)/sizeof(WORD)];
    }
    
    // print_words_inline(in_ihash, sizeof(ixor)/sizeof(WORD)+salt_len); // Problem
    
    sha256_in_words(ctx, in_ihash, in_ihash_len, ihash); // Why it's wrong
    // printf("OK hmac_tes before in_ohash_len\n");
    // print_words_inline(ihash, 8); // OK
    unsigned long in_ohash_len = 24;
 

    
    // printf("in_ohash: %u\n", in_ohash); // 24 --> true
    for(i = 0; i<sizeof(oxor)/sizeof(WORD); i++){
        in_ohash[i] = oxor[i];
        // in_ohash[i] = 0x12341234;
    }
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ohash[i] = ihash[i-sizeof(oxor)/sizeof(WORD)];
    }
    // printf("OK hmac_test in_ohash_len\n");
    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x %d\n", in_ohash[0], in_ohash[1], in_ohash[2], in_ohash[3], in_ohash[4], in_ohash[5], in_ohash[6], in_ohash[7], in_ohash[8], in_ohash[9], in_ohash[10], in_ohash[11], in_ohash[12], in_ohash[13], in_ohash[14], in_ohash[15], in_ohash[16], in_ohash[17], in_ohash[18], in_ohash[19], in_ohash[20], in_ohash[21], in_ohash[22], in_ohash[23], in_ohash_len); // true

    WORD temp[] = {in_ohash[0], in_ohash[1], in_ohash[2], in_ohash[3], in_ohash[4], in_ohash[5], in_ohash[6], in_ohash[7], in_ohash[8], in_ohash[9], in_ohash[10], in_ohash[11], in_ohash[12], in_ohash[13], in_ohash[14], in_ohash[15], in_ohash[16], in_ohash[17], in_ohash[18], in_ohash[19], in_ohash[20], in_ohash[21], in_ohash[22], in_ohash[23]};
    // static WORD ohash[8];
    // printf("\n");
    
    sha256_in_words(ctx, temp, in_ohash_len, out_hmac);
    
    // print_words_inline(out_hmac, 8); // OK
    
    // return ohash;
}
__device__ void pbkdf2(SHA256_CTX_W *ctx, WORD *block, unsigned long block_len, int dklenP, WORD *pbkdf2_out, WORD salt[21]){
    int num_loop = 1024/dklenP;
    // WORD *salt = (WORD*)malloc((block_len+1)*sizeof(WORD));
    WORD *hmac_out = (WORD*)malloc(8*sizeof(WORD));
    // int hmac_out_len = 8;
    
    // printf("pbkdf2: %08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7], block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15], block[16], block[17], block[18], block[19]);
    for(int i = 0; i<block_len; i++){
        salt[i]=block[i];
    }
    
    for (int i = 1; i <= num_loop; i++)
    {
        salt[block_len] = i;
        hmac(ctx, salt, block_len+1, block, block_len, hmac_out);
        // print_words_inline(hmac_out, 8); // False 
        for(int j = 0; j<8; j++){
            pbkdf2_out[(i-1)*8+j] = hmac_out[j];
        }
        // printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", hmac_out[0], hmac_out[1], hmac_out[2], hmac_out[3], hmac_out[4], hmac_out[5], hmac_out[6], hmac_out[7]); // wrong
        // }
    } 
}
__device__ void pbkdf2_test(SHA256_CTX_W *ctx, WORD block[20], unsigned long block_len, WORD pbkdf2_out[32], WORD salt[21], WORD hmac_out[8], WORD khash[8], WORD in_ihash[37], WORD ihash[8], WORD in_ohash[24]){

    // printf("OK\n");

    // int hmac_out_len = 8;
    
    
    // printf("pbkdf2: %08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7], block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15], block[16], block[17], block[18], block[19]);
    for(int i = 0; i<block_len; i++){
        salt[i]=block[i];
    }
    // printf("pbkdf2_out: %u\n", pbkdf2_out); // 24 --> true
    // print_words_multiline(pbkdf2_out, 32);
    for (int i = 1; i <= 4; i++)
    {
        salt[block_len] = i;
        // printf("OK SALT\n");
        hmac_test(ctx, salt, block_len+1, block, block_len, hmac_out, khash, in_ihash, ihash, in_ohash);
        // printf("OK HMAC\n");
        // print_words_inline(hmac_out, 8); // False 
        for(int j = 0; j<8; j++){
            pbkdf2_out[(i-1)*8+j] = hmac_out[j];
            // pbkdf2_out[(i-1)*8+j] = 0xffffffff;
            // printf("%08x, %d\n", pbkdf2_out[(i-1)*8+j], (i-1)*8+j);
            // print_words_multiline(pbkdf2_out, 32);
        }
        // printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", hmac_out[0], hmac_out[1], hmac_out[2], hmac_out[3], hmac_out[4], hmac_out[5], hmac_out[6], hmac_out[7]); // wrong
        // }
        
    
    } 
    // print_words_multiline(pbkdf2_out, 32);

}

__device__ void pbkdf2_2nd(SHA256_CTX_W *ctx, WORD *rm_out, unsigned long rm_out_len, WORD *block, unsigned long block_len, WORD* pbkdf2_out, WORD salt[21], WORD hmac_out[8], WORD khash[8], WORD in_ihash[37], WORD ihash[8], WORD in_ohash[24]){
  

    // int hmac_out_len = 8;
    
    for(int i = 0; i<rm_out_len; i++){
        salt[i]=rm_out[i];
    }


    salt[rm_out_len] = 1;
    
    hmac_2(ctx, salt, rm_out_len+1, block, block_len, hmac_out, khash, in_ihash, ihash, in_ohash);
    
    pbkdf2_out[0] = hmac_out[0];
    for(int j = 0; j<8; j++){
        //pbkdf2_out[(i-1)*8+j] = hmac_out[j];
        pbkdf2_out[j] = hmac_out[j];
        //printf("%d: %08x \n", j, hmac_out[j]);
        // printf("%d: %08x \n", j, hmac_out[j]);
    }

}
__device__ void salsa_mix_func(WORD *des, WORD *a1, WORD *a2, WORD b){
    // printf("%08x \n", *a1);
    WORD sum = *a1 + *a2;
    // printf("0x%08x + 0x%08x = 0x%08x \n", *a1, *a2,  sum);
    WORD rotl = (sum<<b) | (sum>>(32-b));
    WORD xorv = *des ^ rotl;
    
    *des = xorv;
    
}
__device__ void salsa_round(WORD *x1, WORD *x2, WORD *x3, WORD *x4){
    salsa_mix_func(x1, x4, x3, 7);
    // printf("%08x \n", *x1);
    salsa_mix_func(x2, x1, x4, 9);
    salsa_mix_func(x3, x2, x1, 13);
    salsa_mix_func(x4, x3, x2, 18);
}

__device__ WORD * salsa20_8(WORD *x){
    static WORD out[16];
    // for(int i = 0; i<4; i++){
    for(int i = 0; i<4; i++){
        // if(i==0){
        //     printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15] );
        // }
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

__device__ void  blockmix(WORD *block){
    WORD x_arr[16];
    WORD x_arr_cpy[16];
    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7], block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15]);
    for (int i = 0; i < 16; i++){
        x_arr[i] = block[i];                                        // 1
 
    }
    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", x_arr[0], x_arr[1], x_arr[2], x_arr[3], x_arr[4], x_arr[5], x_arr[6], x_arr[7], x_arr[8], x_arr[9], x_arr[10], x_arr[11], x_arr[12], x_arr[13], x_arr[14], x_arr[15]);
    for (int i = 0; i<2; i++){
        for (int j = 0; j < 16; j++){
            x_arr_cpy[j] = x_arr[j] ^ block[j+16];                  // 2


            x_arr[j] ^= block[j+16];                                // 3

        }
        // printf("xcp %08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", x_arr_cpy[0], x_arr_cpy[1], x_arr_cpy[2], x_arr_cpy[3], x_arr_cpy[4], x_arr_cpy[5], x_arr_cpy[6], x_arr_cpy[7], x_arr_cpy[8], x_arr_cpy[9], x_arr_cpy[10], x_arr_cpy[11], x_arr_cpy[12], x_arr_cpy[13], x_arr_cpy[14], x_arr_cpy[15] );
        salsa20_8(x_arr_cpy);
  
        add_two_words_array_512_bit(x_arr, x_arr_cpy);   // 4
        // printf("0x%08x + 0x%08x = 0x%08x\n", a[0], x_arr_cpy[0], x_arr[0]);
        for (int j = 0; j < 16; j++){

            block[(16*i)+j] = x_arr[j];                             // 5

        }
    }
}

__device__ void romix(WORD *block, int N, WORD mem[1024][32]){
    // WORD mem[1024][32];
    
    int j;
     for (int i = 0; i<N; i++){
        for (j = 0; j < 32; j++){
            mem[i][j] = block[j];
            //printf("N: %d, j: %d, i: %d, \n",N, j ,i);
        }
        // if(i == 1023){
            // printf("i: %d, \n",N, i);
        // }
        
        blockmix(block);
        
    }
    
    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7], block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15], block[16], block[17], block[18], block[19], block[20], block[21], block[22], block[23], block[24], block[25], block[26], block[27], block[28], block[29], block[30], block[31]);
    for (int i = 0; i<N; i++){
        j = (block[16] & 0x000003ff);
 
        for (int k = 0; k<32; k++){
            // int a = block[k] ^ mem[j][k];
            // printf("j: %u, i: %u, k: %u\n",j ,i, k);
            block[k] ^= mem[j][k];
            // if(a != block[k])
            
        }
        blockmix(block);
    }
    

}

__device__ void scrypt( SHA256_CTX_W *ctx,\
                        WORD *block, \
                        unsigned long block_len, \
                        WORD scrypt_out[8], \
                        WORD mem[1024][32], \
                        WORD salt[21], \
                        WORD hmac_out[8], \
                        WORD khash[8], \
                        WORD in_ihash[37], \
                        WORD in_2_ihash[49], \
                        WORD ihash[8], \
                        WORD in_ohash[24], \
                        WORD pbkdf2_rm_out[32]){

    // WORD *pbkdf2_1_out = (WORD*)malloc(pbkdf2_out_len_1*sizeof(WORD));
    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7], block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15], block[16], block[17], block[18], block[19]);
    
    // print_words_inline(&block[19], 1);
    // print_words_inline(block, 20); // OK
    pbkdf2_test(ctx, block, block_len, pbkdf2_rm_out, salt, hmac_out, khash, in_ihash, ihash, in_ohash);
    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", pbkdf2_rm_out[0], pbkdf2_rm_out[1], pbkdf2_rm_out[2], pbkdf2_rm_out[3], pbkdf2_rm_out[4], pbkdf2_rm_out[5], pbkdf2_rm_out[6], pbkdf2_rm_out[7], pbkdf2_rm_out[8], pbkdf2_rm_out[9], pbkdf2_rm_out[10], pbkdf2_rm_out[11], pbkdf2_rm_out[12], pbkdf2_rm_out[13], pbkdf2_rm_out[14], pbkdf2_rm_out[15], pbkdf2_rm_out[16], pbkdf2_rm_out[17], pbkdf2_rm_out[18], pbkdf2_rm_out[19], pbkdf2_rm_out[20], pbkdf2_rm_out[21], pbkdf2_rm_out[22], pbkdf2_rm_out[23], pbkdf2_rm_out[24], pbkdf2_rm_out[25], pbkdf2_rm_out[26], pbkdf2_rm_out[27], pbkdf2_rm_out[28], pbkdf2_rm_out[29], pbkdf2_rm_out[30], pbkdf2_rm_out[31]);
    // printf("OK\n");
    // print_words_multiline(pbkdf2_rm_out, 32);
    endian_full(pbkdf2_rm_out, 32);
  
    
    romix(pbkdf2_rm_out, 1024, mem);
    
    
    // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", pbkdf2_rm_out[0], pbkdf2_rm_out[1], pbkdf2_rm_out[2], pbkdf2_rm_out[3], pbkdf2_rm_out[4], pbkdf2_rm_out[5], pbkdf2_rm_out[6], pbkdf2_rm_out[7], pbkdf2_rm_out[8], pbkdf2_rm_out[9], pbkdf2_rm_out[10], pbkdf2_rm_out[11], pbkdf2_rm_out[12], pbkdf2_rm_out[13], pbkdf2_rm_out[14], pbkdf2_rm_out[15], pbkdf2_rm_out[16], pbkdf2_rm_out[17], pbkdf2_rm_out[18], pbkdf2_rm_out[19], pbkdf2_rm_out[20], pbkdf2_rm_out[21], pbkdf2_rm_out[22], pbkdf2_rm_out[23], pbkdf2_rm_out[24], pbkdf2_rm_out[25], pbkdf2_rm_out[26], pbkdf2_rm_out[27], pbkdf2_rm_out[28], pbkdf2_rm_out[29], pbkdf2_rm_out[30], pbkdf2_rm_out[31]);
    
    endian_full(pbkdf2_rm_out, 32);
    // print_words_multiline(pbkdf2_1_out, 32);
    
    pbkdf2_2nd(ctx, pbkdf2_rm_out, 32, block, block_len, scrypt_out, salt, hmac_out, khash, in_2_ihash, ihash, in_ohash);

    // printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", pbkdf2_2_out[0],pbkdf2_2_out[1],pbkdf2_2_out[2],pbkdf2_2_out[3],pbkdf2_2_out[4],pbkdf2_2_out[5],pbkdf2_2_out[6],pbkdf2_2_out[7]);
    // print_words_inline(pbkdf2_2_out, 20);
}






cudaError_t scryptWithCuda(SCRYPT_PKG **pkgs, int block_per_grid, int thread_per_block);




__global__ void scryptCuda(SCRYPT_PKG **pkgs)
{   
    int threadId = blockDim.x * blockIdx.x + threadIdx.x;
    // int blockId = blockIdx.y*gridDim.x+blockIdx.x;
    // uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    // uint32_t stride = blockDim.x * gridDim.x;
    // char hex_str[65];
    SHA256_CTX *ctx = new SHA256_CTX();
    // int i;
    
    // for (i = 0; i<3000000000; i++){
       
    // }
    //WORD T_Nonce = pkgs[threadId]->input[19];
    
    if(threadId < NUMTHREAD){
        // for (uint32_t threadId = index; threadId < MAXNONCE; threadId += stride){
            WORD T_Nonce = pkgs[threadId]->input[19];
            endian_cvt(&T_Nonce);
            // if(threadId == 1024)
                // printf("Thread id %d: %08x maxnonce: %u\n", threadId, T_Nonce, MAXNONCE/NUMTHREAD);
        for(int i = 0; i<MAXNONCE/NUMTHREAD; i++){
            // if(threadId == NUMTHREAD-1 && i==MAXNONCE/NUMTHREAD-1){
            //     // print_words_inline(&in[20*threadId+19], 1);
            //     // printf("Thread ID (%d) = %08x%08x%08x%08x%08x%08x%08x%08x\n", threadId, out[8*threadId],out[8*threadId+1],out[8*threadId+2],out[8*threadId+3],out[8*threadId+4],out[8*threadId+5],out[8*threadId+6],out[8*threadId+7]);
            // }
            // printf("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", pkgs[threadId]->input[0],pkgs[threadId]->input[1],pkgs[threadId]->input[2],pkgs[threadId]->input[3],pkgs[threadId]->input[4],pkgs[threadId]->input[5],pkgs[threadId]->input[6],pkgs[threadId]->input[7], pkgs[threadId]->input[8], pkgs[threadId]->input[9], pkgs[threadId]->input[10], pkgs[threadId]->input[11], pkgs[threadId]->input[12], pkgs[threadId]->input[13], pkgs[threadId]->input[14], pkgs[threadId]->input[15], pkgs[threadId]->input[16], pkgs[threadId]->input[17], pkgs[threadId]->input[18], pkgs[threadId]->input[19]);
            //printf("Thread id  %08x \n",pkgs[threadId]->input[19]);
            scrypt(     &(pkgs[threadId]->ctx), \
                        pkgs[threadId]->input, \
                        20, \
                        pkgs[threadId]->output, \
                        pkgs[threadId]->mem, \
                        pkgs[threadId]->salt, \
                        pkgs[threadId]->hmac_out, \
                        pkgs[threadId]->khash, \
                        pkgs[threadId]->in_ihash, \
                        pkgs[threadId]->in_2_ihash, \
                        pkgs[threadId]->ihash, \
                        pkgs[threadId]->in_ohash, \
                        pkgs[threadId]->pbkdf2_rm_out\
                    );
            // printf("!!!!Hello\n");
            // if(threadId == NUMTHREAD-1){
            //     // printf("i: %d\n", i);
            // }
            if(threadId == NUMTHREAD-1 && i==MAXNONCE/NUMTHREAD-1){
                 printf("Thread ID (%d) = %08x%08x%08x%08x%08x%08x%08x%08x\n", threadId, pkgs[threadId]->output[0],pkgs[threadId]->output[1],pkgs[threadId]->output[2],pkgs[threadId]->output[3],pkgs[threadId]->output[4],pkgs[threadId]->output[5],pkgs[threadId]->output[6],pkgs[threadId]->output[7]);
            }

            endian_cvt(&pkgs[threadId]->input[19]);
            pkgs[threadId]->input[19]++;
            // printf("Thread id %d: %u maxnonce: %u\n", threadId, pkgs[threadId]->input[19], MAXNONCE/NUMTHREAD);
            endian_cvt(&pkgs[threadId]->input[19]);
        }
        // printf("[%d]\n",\
        // threadId);
        
        // words_to_hex_string(out[threadId], 8, hex_str, 64);
        // printf("Thread ID: %d, %s", threadId, hex_str);
        // print_words_inline(&out[threadId], 8);
        

    }

}

int main()
{
  
    
    // static char test_scrypt_in[] =     "0000002056efd1943684c1fdc247d4759cc43b29afa1cac7ad14579de5f6abcbc6bdf448ee3de4c7b45e9496ab41ecde73d1a299ddbcc7a81aa52776e6c067e214233af097b6885c97df011aa004090e";
    // static char test_scrypt_in[] =     "0000002056efd1943684c1fdc247d4759cc43b29afa1cac7ad14579de5f6abcbc6bdf448ee3de4c7b45e9496ab41ecde73d1a299ddbcc7a81aa52776e6c067e214233af097b6885c97df011a";

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
    endian_cvt_host(wtime);
    word_to_hex_eight_host(*wtime, time, 8);

    word_to_hex_eight_host(436330391, bits, 8); // bits -- input
    little_endian(bits, 8);
    char test_scrypt_in[153];
   

  
    int in_index = 0;
    for(int i = 0; i < sizeof(ver)-1; i++){
        test_scrypt_in[i]=ver[i];
    }
    in_index += sizeof(ver)-1;
    for(int i = 0; i < sizeof(prev_block); i++){
        test_scrypt_in[in_index+i] = prev_block[i];
    }
    in_index += sizeof(prev_block)-1;
    for(int i = 0; i < sizeof(mrkl_root); i++){
        test_scrypt_in[in_index+i] = mrkl_root[i];
    }
    in_index += sizeof(mrkl_root)-1;
    for(int i = 0; i < sizeof(time); i++){
        test_scrypt_in[in_index+i] = time[i];
    }
    in_index += sizeof(time)-1;
    for(int i = 0; i < sizeof(bits); i++){
        test_scrypt_in[in_index+i] = bits[i];
    }
    WORD *nonce = (WORD*) malloc(sizeof(WORD));
    // WORD *nonce = new WORD(235472032);
    
    // WORD test_scrypt_out_w[8][NUMTHREAD];
    
    
    SCRYPT_PKG **pkgs = (SCRYPT_PKG**)malloc(NUMTHREAD*sizeof(SCRYPT_PKG*));

    // for(int k = 0; k<NUMTHREAD; k++){
    //     hex_string_to_words_host(test_scrypt_in, sizeof(test_scrypt_in), &test_scrypt_in_w[20*k]);
    //     *nonce = STARTATNONCE + (k * (MAXNONCE/NUMTHREAD));
    //     endian_cvt_host(nonce);
    //     test_scrypt_in_w[20*k+19] = *nonce;
        
    // }
    for(int k = 0; k<NUMTHREAD; k++){
        pkgs[k] = (SCRYPT_PKG*)malloc(sizeof(SCRYPT_PKG));
        hex_string_to_words_host(test_scrypt_in, sizeof(test_scrypt_in), pkgs[k]->input);
        *nonce = STARTATNONCE + (k * (MAXNONCE/NUMTHREAD));
        endian_cvt_host(nonce);
        pkgs[k]->input[19] = *nonce;
        // printf("%d \n", pkgs[k]);
        // printf("%08x", pkgs[k]->input);
        // print_words_inline_host(pkgs[k]->input, 20);
    }
   
    uint32_t threadsPerBlock = BLOCKSIZE;
    uint32_t blocksPerGrid =(threadsPerBlock + MAXNONCE - 1) / threadsPerBlock;
    // Add vectors in parallel.
    cudaError_t cudaStatus = scryptWithCuda(pkgs, blocksPerGrid, threadsPerBlock);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "scryptWithCuda failed!\n");
        return 1;
    }

    // cudaDeviceReset must be called before exiting in order for profiling and
    // tracing tools such as Nsight and Visual Profiler to show complete traces.
    cudaStatus = cudaDeviceReset();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaDeviceReset failed!");
        return 1;
    }

    return 0;
}

SCRYPT_PKG* pkg_init(WORD* indata){
    SCRYPT_PKG* pkg;
    cudaMallocManaged(&pkg, sizeof(SCRYPT_PKG));
    for (int j = 0; j < 20; j++){
        pkg->input[j] = indata[j];
        // printf("%08x\n", pkg->input[j]);
    }
    return pkg;
}

// Helper function for using CUDA to add vectors in parallel.
cudaError_t scryptWithCuda(SCRYPT_PKG **pkgs, int block_per_grid, int thread_per_block)
{
    SCRYPT_PKG **pkgs_dev;
    cudaError_t cudaStatus;
    // SCRYPT_PKG *pkg_pointer;
    // Choose which GPU to run on, change this on a multi-GPU system.
    cudaStatus = cudaSetDevice(0);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
        goto Error;
    }

    // Allocate GPU buffers for three vectors (two input, one output)    .
    cudaStatus = cudaMallocManaged((void**)&pkgs_dev, NUMTHREAD * sizeof(SCRYPT_PKG*));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }

    for(int i = 0; i<NUMTHREAD; i++){
        
        // Copy input vectors from host memory to GPU buffers.

        pkgs_dev[i] = pkg_init(pkgs[i]->input);
        // print_words_inline_host(pkgs[i]->input, 20);
        // printf("    %08x\n", pkgs_dev[i]);
        // cudaStatus = cudaMemcpy(pkgs_dev[i]->input, pkgs[i]->input, 20*sizeof(WORD), cudaMemcpyHostToDevice);
        // if (cudaStatus != cudaSuccess) {
        //     fprintf(stderr, "cudaMemcpy failed!");
        //     goto Error;
        // }
    }

    // Launch a kernel on the GPU with one thread for each element.

    scryptCuda<<<block_per_grid, thread_per_block>>>(pkgs_dev);

    // Check for any errors launching the kernel
    cudaStatus = cudaGetLastError();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "scryptCuda launch failed: %s\n", cudaGetErrorString(cudaStatus));
        goto Error;
    }
    
    // cudaDeviceSynchronize waits for the kernel to finish, and returns
    // any errors encountered during the launch.
    cudaStatus = cudaDeviceSynchronize();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaDeviceSynchronize returned error code %d after launching scryptCuda!\n", cudaStatus);
        goto Error;
    }

    // // Copy output vector from GPU buffer to host memory.

    // cudaStatus = cudaMemcpy(out, dev_out, NUMTHREAD * 8 * sizeof(WORD), cudaMemcpyDeviceToHost);
    // if (cudaStatus != cudaSuccess) {
    //     fprintf(stderr, "cudaMemcpy launch failed: %s\n", cudaGetErrorString(cudaStatus));
    //     goto Error;
    // }


Error:
    
    cudaFree(pkgs_dev);
    
    return cudaStatus;
}

